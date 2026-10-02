//! RDF, and its canonical form: what a Linked Data Signature signs.
//!
//! A Linked Data Signature (`RsaSignature2017`, which Mastodon makes and
//! checks) does not sign the JSON. It signs the RDF dataset the JSON-LD
//! means, written out in the canonical N-Quads that the URDNA2015 algorithm
//! gives — so two documents that say the same thing in different words carry
//! the same signature, and verifying one means turning it into RDF exactly as
//! its signer did.
//!
//! [`canonize`] does that, from expansion in this crate, through the JSON-LD
//! 1.1 "Deserialize JSON-LD to RDF" algorithm, to the "Universal RDF Dataset
//! Normalization Algorithm 2015" ([URDNA2015], which RDFC-1.0 standardised
//! without changing its output).
//!
//! Two things make it stricter than a general processor, both deliberate:
//!
//!  -  A context ojak does not ship is an error here, not ActivityStreams. A
//!     signer resolved it to something; without it, the dataset cannot be
//!     rebuilt, and guessing would only make the signature fail later.
//!  -  The work is bounded. Expansion is held to [`Limits`]; the blank-node
//!     labelling, whose worst case is factorial in the number of blank nodes
//!     that look alike, is held to a budget of its own and gives up with
//!     [`Error::CanonicalizationBudgetExceeded`] rather than run away.
//!
//! [URDNA2015]: https://www.w3.org/TR/rdf-canon/

use alloc::{
    borrow::ToOwned,
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    vec::Vec,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    Error, Limits, Registry,
    context::{ActiveContext, Session, is_absolute_iri},
    expand,
};

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_FIRST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first";
const RDF_REST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest";
const RDF_NIL: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil";
const RDF_LANG_STRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const XSD_BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";
const XSD_INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
const XSD_DOUBLE: &str = "http://www.w3.org/2001/XMLSchema#double";

/// How many steps the blank-node labelling may take for one dataset.
///
/// Each step is one call of "Hash N-Degree Quads" or one permutation it
/// tries. An ActivityPub document has a handful of blank nodes, nearly all
/// told apart at the first degree, and takes none.
const CANONICALIZATION_BUDGET: usize = 4_096;

/// A node or value in an RDF statement.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Term {
    /// An absolute IRI.
    Iri(String),
    /// A blank node, by its label without the leading `_:`.
    Blank(String),
    /// A literal: its lexical form, its datatype IRI, and its language tag
    /// when the datatype is `rdf:langString`.
    Literal {
        value: String,
        datatype: String,
        language: Option<String>,
    },
}

/// One RDF statement, in the default graph or a named one.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Quad {
    pub subject: Term,
    pub predicate: String,
    pub object: Term,
    /// `None` for the default graph.
    pub graph: Option<Term>,
}

/// Expand `document` the way RDF needs it, refusing a context ojak does not
/// ship.
///
/// The result differs from [`crate::expand`] in two places, both where
/// ojak's reading expansion drops what says nothing to a tree reader but
/// is a statement in RDF: a node object with no properties is kept (it is a
/// blank node something points at), and a term whose `@container` is
/// `@graph` wraps its values in a graph object.
pub fn expand_for_rdf(
    registry: &Registry,
    document: &Value,
    limits: Limits,
) -> Result<Value, Error> {
    let mut session = Session::new(registry, limits);
    session.rdf = true;
    let expanded = expand::expand_document(&ActiveContext::default(), document, &mut session)?;
    if let Some(unresolved) = session.unresolved.into_iter().next() {
        return Err(Error::UnresolvedContext(unresolved));
    }
    Ok(expanded)
}

/// The canonical N-Quads of `document`: what an `RsaSignature2017` hashes.
pub fn canonize(registry: &Registry, document: &Value) -> Result<String, Error> {
    canonize_with(registry, document, Limits::default())
}

/// [`canonize`], with limits of the caller's choosing.
pub fn canonize_with(
    registry: &Registry,
    document: &Value,
    limits: Limits,
) -> Result<String, Error> {
    let expanded = expand_for_rdf(registry, document, limits)?;
    let quads = to_rdf(&expanded)?;
    canonicalize(&quads)
}

/// The JSON-LD "Deserialize JSON-LD to RDF" algorithm, over a document
/// [`expand_for_rdf`] expanded.
///
/// Statements naming a relative IRI, or a blank node as a predicate, are left
/// out, as the algorithm leaves them out; so is a literal whose language tag
/// is not well formed.
pub fn to_rdf(expanded: &Value) -> Result<Vec<Quad>, Error> {
    let mut writer = Writer::default();
    match expanded {
        Value::Array(items) => {
            for item in items {
                writer.node(item, None)?;
            }
        }
        item => {
            writer.node(item, None)?;
        }
    }
    let mut quads = writer.quads;
    quads.sort();
    quads.dedup();
    Ok(quads)
}

#[derive(Default)]
struct Writer {
    quads: Vec<Quad>,
    /// Labels the document gave its blank nodes, and what they became.
    labels: BTreeMap<String, String>,
    next: usize,
}

impl Writer {
    fn fresh(&mut self) -> String {
        let label = format!("b{}", self.next);
        self.next += 1;
        label
    }

    /// The term for a node's `@id`: an IRI, a blank node relabelled, or
    /// `None` for a relative IRI, which RDF cannot name.
    fn id_term(&mut self, id: &str) -> Option<Term> {
        if let Some(label) = id.strip_prefix("_:") {
            if let Some(mapped) = self.labels.get(label) {
                return Some(Term::Blank(mapped.clone()));
            }
            let mapped = self.fresh();
            self.labels.insert(label.to_owned(), mapped.clone());
            return Some(Term::Blank(mapped));
        }
        well_formed_iri(id).then(|| Term::Iri(id.to_owned()))
    }

    fn emit(&mut self, subject: &Term, predicate: &str, object: Term, graph: &Option<Term>) {
        self.quads.push(Quad {
            subject: subject.clone(),
            predicate: predicate.to_owned(),
            object,
            graph: graph.clone(),
        });
    }

    /// Write a node object's statements into `graph`, returning the term
    /// that names it (`None` when its `@id` is a relative IRI).
    fn node(&mut self, node: &Value, graph: Option<Term>) -> Result<Option<Term>, Error> {
        let Value::Object(map) = node else {
            return Ok(None);
        };
        if map.contains_key("@value") || map.contains_key("@list") {
            // A value at the top level is a statement about nothing.
            return Ok(None);
        }
        if let Some(contents) = map.get("@graph") {
            return self.graph_object(map, contents);
        }
        let subject = match map.get("@id").and_then(Value::as_str) {
            Some(id) => self.id_term(id),
            None => Some(Term::Blank(self.fresh())),
        };

        let mut keys: Vec<&String> = map.keys().collect();
        keys.sort();
        for key in keys {
            let values = match &map[key] {
                Value::Array(items) => items.as_slice(),
                single => core::slice::from_ref(single),
            };
            match key.as_str() {
                "@id" => {}
                "@type" => {
                    for kind in values {
                        let Some(kind) = kind.as_str() else { continue };
                        let object = self.id_term(kind);
                        if let (Some(subject), Some(object)) = (&subject, object) {
                            self.emit(subject, RDF_TYPE, object, &graph);
                        }
                    }
                }
                key if key.starts_with('@') => {}
                property => {
                    let usable = well_formed_iri(property);
                    for value in values {
                        let object = self.object(value, &graph)?;
                        if let (true, Some(subject), Some(object)) = (usable, &subject, object) {
                            self.emit(subject, property, object, &graph);
                        }
                    }
                }
            }
        }
        Ok(subject)
    }

    /// A graph object: its nodes go into a graph named by its `@id`, or by a
    /// fresh blank node, and that name is what refers to it.
    fn graph_object(
        &mut self,
        map: &Map<String, Value>,
        contents: &Value,
    ) -> Result<Option<Term>, Error> {
        let name = match map.get("@id").and_then(Value::as_str) {
            Some(id) => self.id_term(id),
            None => Some(Term::Blank(self.fresh())),
        };
        let items = match contents {
            Value::Array(items) => items.as_slice(),
            single => core::slice::from_ref(single),
        };
        for item in items {
            // Statements whose graph cannot be named are not statements.
            if name.is_some() {
                self.node(item, name.clone())?;
            }
        }
        Ok(name)
    }

    /// The term for one value of a property, writing whatever it needs: a
    /// node's own statements, or a list's cells.
    fn object(&mut self, value: &Value, graph: &Option<Term>) -> Result<Option<Term>, Error> {
        let Value::Object(map) = value else {
            return Ok(None);
        };
        if map.contains_key("@value") {
            return literal(map);
        }
        if let Some(items) = map.get("@list") {
            let items = match items {
                Value::Array(items) => items.as_slice(),
                single => core::slice::from_ref(single),
            };
            return self.list(items, graph);
        }
        self.node(value, graph.clone())
    }

    /// The JSON-LD "List to RDF Conversion" algorithm.
    fn list(&mut self, items: &[Value], graph: &Option<Term>) -> Result<Option<Term>, Error> {
        if items.is_empty() {
            return Ok(Some(Term::Iri(RDF_NIL.to_owned())));
        }
        let cells: Vec<Term> = items.iter().map(|_| Term::Blank(self.fresh())).collect();
        for (index, item) in items.iter().enumerate() {
            let cell = &cells[index];
            if let Some(object) = self.object(item, graph)? {
                self.emit(cell, RDF_FIRST, object, graph);
            }
            let rest = cells
                .get(index + 1)
                .cloned()
                .unwrap_or_else(|| Term::Iri(RDF_NIL.to_owned()));
            self.emit(cell, RDF_REST, rest, graph);
        }
        Ok(cells.into_iter().next())
    }
}

/// The JSON-LD "Object to RDF Conversion" algorithm, for a value object.
fn literal(map: &Map<String, Value>) -> Result<Option<Term>, Error> {
    let value = &map["@value"];
    let datatype = map.get("@type").and_then(Value::as_str);
    if datatype == Some("@json") {
        return Err(Error::Unsupported("@json literal".to_owned()));
    }
    if let Some(datatype) = datatype
        && !well_formed_iri(datatype)
    {
        return Ok(None);
    }
    let language = map.get("@language").and_then(Value::as_str);
    let (lexical, datatype) = match value {
        Value::Bool(flag) => (
            if *flag { "true" } else { "false" }.to_owned(),
            datatype.unwrap_or(XSD_BOOLEAN).to_owned(),
        ),
        Value::Number(number) => {
            let double = number.as_f64().unwrap_or(0.0);
            // Every double from 2^53 up is integral; below, one is when it
            // survives a round trip through an integer.
            #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
            let integral = number.is_i64()
                || number.is_u64()
                || double.abs() >= 9_007_199_254_740_992.0
                || (double as i64) as f64 == double;
            if !integral || double.abs() >= 1e21 || datatype == Some(XSD_DOUBLE) {
                (
                    canonical_double(double),
                    datatype.unwrap_or(XSD_DOUBLE).to_owned(),
                )
            } else {
                let lexical = if let Some(integer) = number.as_i64() {
                    integer.to_string()
                } else if let Some(integer) = number.as_u64() {
                    integer.to_string()
                } else {
                    // An integral double below 10^21: written without a
                    // fraction, as the integer it is.
                    format!("{double:.0}")
                };
                (lexical, datatype.unwrap_or(XSD_INTEGER).to_owned())
            }
        }
        Value::String(text) => match (language, datatype) {
            (Some(language), _) => {
                if !well_formed_language(language) {
                    return Ok(None);
                }
                return Ok(Some(Term::Literal {
                    value: text.clone(),
                    datatype: RDF_LANG_STRING.to_owned(),
                    language: Some(language.to_owned()),
                }));
            }
            (None, Some(datatype)) => (text.clone(), datatype.to_owned()),
            (None, None) => (text.clone(), XSD_STRING.to_owned()),
        },
        _ => {
            return Err(Error::Unsupported(
                "a value object whose @value is not a scalar".to_owned(),
            ));
        }
    };
    Ok(Some(Term::Literal {
        value: lexical,
        datatype,
        language: None,
    }))
}

/// XSD's canonical double, as JSON-LD writes it: `%1.15E` with the fraction's
/// trailing zeros removed, one digit kept (`5.0E-1`, `1.0E21`).
fn canonical_double(value: f64) -> String {
    if value == 0.0 {
        // Negative zero too: RDF.rb writes both as the one zero.
        return "0.0E0".to_owned();
    }
    let formatted = format!("{value:.15E}");
    let (mantissa, exponent) = formatted.split_once('E').unwrap_or((&formatted, "0"));
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let fraction = fraction.trim_end_matches('0');
    let fraction = if fraction.is_empty() { "0" } else { fraction };
    format!("{whole}.{fraction}E{exponent}")
}

/// An absolute IRI, as RFC 3987 has it: a statement naming anything else —
/// a relative reference, or `a#b#c` — is not one.
fn well_formed_iri(value: &str) -> bool {
    is_absolute_iri(value) && iri_string::types::IriStr::new(value).is_ok()
}

/// BCP 47 as N-Quads reads it: `[a-zA-Z]+ ('-' [a-zA-Z0-9]+)*`.
fn well_formed_language(tag: &str) -> bool {
    let mut parts = tag.split('-');
    let first = parts.next().unwrap_or("");
    !first.is_empty()
        && first.chars().all(|c| c.is_ascii_alphabetic())
        && parts.all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// URDNA2015: the dataset's canonical N-Quads, one statement a line, sorted.
pub fn canonicalize(quads: &[Quad]) -> Result<String, Error> {
    let mut state = Canonicalizer::new(quads);
    state.label()?;
    let mut lines: Vec<String> = quads
        .iter()
        .map(|quad| state.relabelled(quad))
        .map(|quad| nquad(&quad))
        .collect();
    lines.sort();
    lines.dedup();
    Ok(lines.concat())
}

/// An identifier issuer: hands out `prefix0`, `prefix1`, … in order, the same
/// one each time it is asked about the same blank node.
#[derive(Clone, Debug)]
struct Issuer {
    prefix: &'static str,
    issued: BTreeMap<String, String>,
    order: Vec<String>,
}

impl Issuer {
    fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            issued: BTreeMap::new(),
            order: Vec::new(),
        }
    }

    fn issue(&mut self, existing: &str) -> String {
        if let Some(issued) = self.issued.get(existing) {
            return issued.clone();
        }
        let issued = format!("{}{}", self.prefix, self.order.len());
        self.issued.insert(existing.to_owned(), issued.clone());
        self.order.push(existing.to_owned());
        issued
    }

    fn get(&self, existing: &str) -> Option<&String> {
        self.issued.get(existing)
    }
}

struct Canonicalizer<'a> {
    quads: &'a [Quad],
    /// Each blank node, and the statements mentioning it.
    mentions: BTreeMap<String, Vec<usize>>,
    canonical: Issuer,
    first_degree: BTreeMap<String, String>,
    budget: usize,
}

fn blank(term: &Term) -> Option<&str> {
    match term {
        Term::Blank(label) => Some(label),
        _ => None,
    }
}

impl<'a> Canonicalizer<'a> {
    fn new(quads: &'a [Quad]) -> Self {
        let mut mentions: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, quad) in quads.iter().enumerate() {
            let mut seen = BTreeSet::new();
            for term in [Some(&quad.subject), Some(&quad.object), quad.graph.as_ref()]
                .into_iter()
                .flatten()
            {
                if let Some(label) = blank(term)
                    && seen.insert(label)
                {
                    mentions.entry(label.to_owned()).or_default().push(index);
                }
            }
        }
        Self {
            quads,
            mentions,
            canonical: Issuer::new("c14n"),
            first_degree: BTreeMap::new(),
            budget: CANONICALIZATION_BUDGET,
        }
    }

    fn spend(&mut self) -> Result<(), Error> {
        self.budget = self
            .budget
            .checked_sub(1)
            .ok_or(Error::CanonicalizationBudgetExceeded)?;
        Ok(())
    }

    /// Steps 3 to 6 of the algorithm: every blank node gets its canonical
    /// label.
    fn label(&mut self) -> Result<(), Error> {
        let nodes: Vec<String> = self.mentions.keys().cloned().collect();
        let mut by_hash: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for node in &nodes {
            let hash = self.hash_first_degree(node);
            by_hash.entry(hash).or_default().push(node.clone());
        }
        // A hash only one node has names that node.
        let mut shared = Vec::new();
        for (_, group) in by_hash {
            if group.len() == 1 {
                self.canonical.issue(&group[0]);
            } else {
                shared.push(group);
            }
        }
        for group in shared {
            let mut results = Vec::new();
            for node in group {
                if self.canonical.get(&node).is_some() {
                    continue;
                }
                let mut issuer = Issuer::new("b");
                issuer.issue(&node);
                results.push(self.hash_n_degree(&node, issuer)?);
            }
            results.sort_by(|a, b| a.0.cmp(&b.0));
            for (_, issuer) in results {
                for existing in &issuer.order {
                    self.canonical.issue(existing);
                }
            }
        }
        Ok(())
    }

    /// "Hash First Degree Quads".
    fn hash_first_degree(&mut self, node: &str) -> String {
        if let Some(hash) = self.first_degree.get(node) {
            return hash.clone();
        }
        let mut lines: Vec<String> = self.mentions[node]
            .iter()
            .map(|&index| {
                let quad = &self.quads[index];
                let mark = |term: &Term| match term {
                    Term::Blank(label) if label == node => Term::Blank("a".to_owned()),
                    Term::Blank(_) => Term::Blank("z".to_owned()),
                    other => other.clone(),
                };
                nquad(&Quad {
                    subject: mark(&quad.subject),
                    predicate: quad.predicate.clone(),
                    object: mark(&quad.object),
                    graph: quad.graph.as_ref().map(mark),
                })
            })
            .collect();
        lines.sort();
        let hash = sha256_hex(lines.concat().as_bytes());
        self.first_degree.insert(node.to_owned(), hash.clone());
        hash
    }

    /// "Hash Related Blank Node".
    fn hash_related(
        &mut self,
        related: &str,
        quad: &Quad,
        issuer: &Issuer,
        position: &str,
    ) -> String {
        let identifier = match (self.canonical.get(related), issuer.get(related)) {
            (Some(id), _) | (None, Some(id)) => format!("_:{id}"),
            (None, None) => self.hash_first_degree(related),
        };
        let mut input = String::from(position);
        if position != "g" {
            input.push('<');
            input.push_str(&quad.predicate);
            input.push('>');
        }
        input.push_str(&identifier);
        sha256_hex(input.as_bytes())
    }

    /// "Hash N-Degree Quads".
    fn hash_n_degree(&mut self, node: &str, mut issuer: Issuer) -> Result<(String, Issuer), Error> {
        self.spend()?;
        let mut related_by_hash: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mentions = self.mentions[node].clone();
        for index in mentions {
            let quad = &self.quads[index];
            for (term, position) in [
                (Some(&quad.subject), "s"),
                (Some(&quad.object), "o"),
                (quad.graph.as_ref(), "g"),
            ] {
                let Some(related) = term.and_then(blank) else {
                    continue;
                };
                if related == node {
                    continue;
                }
                let hash = self.hash_related(related, quad, &issuer, position);
                related_by_hash
                    .entry(hash)
                    .or_default()
                    .push(related.to_owned());
            }
        }

        let mut data = String::new();
        for (hash, related) in related_by_hash {
            data.push_str(&hash);
            let mut chosen_path = String::new();
            let mut chosen_issuer: Option<Issuer> = None;
            for permutation in permutations(&related) {
                self.spend()?;
                let mut issuer_copy = issuer.clone();
                let mut path = String::new();
                let mut recursion = Vec::new();
                let mut skip = false;
                for node in &permutation {
                    if let Some(id) = self.canonical.get(node) {
                        path.push_str("_:");
                        path.push_str(id);
                    } else {
                        if issuer_copy.get(node).is_none() {
                            recursion.push(node.clone());
                        }
                        path.push_str("_:");
                        path.push_str(&issuer_copy.issue(node));
                    }
                    if !chosen_path.is_empty()
                        && path.len() >= chosen_path.len()
                        && path > chosen_path
                    {
                        skip = true;
                        break;
                    }
                }
                if skip {
                    continue;
                }
                for node in recursion {
                    let (result_hash, result_issuer) =
                        self.hash_n_degree(&node, issuer_copy.clone())?;
                    path.push_str("_:");
                    path.push_str(&issuer_copy.issue(&node));
                    path.push('<');
                    path.push_str(&result_hash);
                    path.push('>');
                    issuer_copy = result_issuer;
                    if !chosen_path.is_empty()
                        && path.len() >= chosen_path.len()
                        && path > chosen_path
                    {
                        skip = true;
                        break;
                    }
                }
                if skip {
                    continue;
                }
                if chosen_path.is_empty() || path < chosen_path {
                    chosen_path = path;
                    chosen_issuer = Some(issuer_copy);
                }
            }
            data.push_str(&chosen_path);
            if let Some(chosen) = chosen_issuer {
                issuer = chosen;
            }
        }
        Ok((sha256_hex(data.as_bytes()), issuer))
    }

    fn relabelled(&self, quad: &Quad) -> Quad {
        let relabel = |term: &Term| match term {
            Term::Blank(label) => Term::Blank(
                self.canonical
                    .get(label)
                    .cloned()
                    .unwrap_or_else(|| label.clone()),
            ),
            other => other.clone(),
        };
        Quad {
            subject: relabel(&quad.subject),
            predicate: quad.predicate.clone(),
            object: relabel(&quad.object),
            graph: quad.graph.as_ref().map(relabel),
        }
    }
}

/// Every ordering of `items`, one at a time: all of them at once would be
/// factorial in memory before the budget had a say.
struct Permutations<'a> {
    items: &'a [String],
    order: Option<Vec<usize>>,
}

fn permutations(items: &[String]) -> Permutations<'_> {
    Permutations {
        items,
        order: Some((0..items.len()).collect()),
    }
}

impl Iterator for Permutations<'_> {
    type Item = Vec<String>;

    fn next(&mut self) -> Option<Vec<String>> {
        let order = self.order.as_mut()?;
        let current = order.iter().map(|&i| self.items[i].clone()).collect();
        // The next ordering in lexicographic order of the indices, or none.
        match (1..order.len()).rev().find(|&i| order[i - 1] < order[i]) {
            Some(pivot) => {
                let swap = (pivot..order.len())
                    .rev()
                    .find(|&j| order[j] > order[pivot - 1])
                    .unwrap_or(pivot);
                order.swap(pivot - 1, swap);
                order[pivot..].reverse();
            }
            None => self.order = None,
        }
        Some(current)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// One statement in canonical N-Quads, with its line ending.
fn nquad(quad: &Quad) -> String {
    let mut line = String::new();
    write_term(&mut line, &quad.subject);
    line.push_str(" <");
    line.push_str(&quad.predicate);
    line.push_str("> ");
    write_term(&mut line, &quad.object);
    if let Some(graph) = &quad.graph {
        line.push(' ');
        write_term(&mut line, graph);
    }
    line.push_str(" .\n");
    line
}

fn write_term(out: &mut String, term: &Term) {
    match term {
        Term::Iri(iri) => {
            out.push('<');
            out.push_str(iri);
            out.push('>');
        }
        Term::Blank(label) => {
            out.push_str("_:");
            out.push_str(label);
        }
        Term::Literal {
            value,
            datatype,
            language,
        } => {
            out.push('"');
            for c in value.chars() {
                match c {
                    '\\' => out.push_str("\\\\"),
                    '"' => out.push_str("\\\""),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\u{8}' => out.push_str("\\b"),
                    '\u{c}' => out.push_str("\\f"),
                    c if (c as u32) < 0x20 || c == '\u{7f}' => {
                        out.push_str(&format!("\\u{:04X}", c as u32));
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
            if let Some(language) = language {
                out.push('@');
                out.push_str(language);
            } else if datatype != XSD_STRING {
                out.push_str("^^<");
                out.push_str(datatype);
                out.push('>');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_are_written_as_xsd_writes_them() {
        assert_eq!(canonical_double(0.5), "5.0E-1");
        assert_eq!(canonical_double(-0.5), "-5.0E-1");
        assert_eq!(canonical_double(0.0), "0.0E0");
        assert_eq!(canonical_double(-0.0), "0.0E0");
        assert_eq!(canonical_double(1e22), "1.0E22");
        assert_eq!(canonical_double(0.300_000_000_000_000_04), "3.0E-1");
        assert_eq!(canonical_double(1.25), "1.25E0");
    }

    #[test]
    fn every_ordering_is_tried_once() {
        let items: Vec<String> = ["a", "b", "c"].iter().map(|s| (*s).to_owned()).collect();
        let all: Vec<String> = permutations(&items).map(|p| p.concat()).collect();
        assert_eq!(all, ["abc", "acb", "bac", "bca", "cab", "cba"]);
        assert_eq!(permutations(&[]).count(), 1);
    }

    #[test]
    fn language_tags_are_checked() {
        assert!(well_formed_language("en"));
        assert!(well_formed_language("zh-hant-tw"));
        assert!(!well_formed_language("en_US"));
        assert!(!well_formed_language(""));
        assert!(!well_formed_language("en-"));
    }
}

//! The vocabulary in Ojak's terms.
//!
//! [`crate::schema`] is the schemas as written; this is what they mean for
//! generated Rust: which Rust type each property's values take, the key each
//! property has in a document `ojak_vocab::read` produced, and the full set
//! of properties each type has once its ancestors' are included.

use crate::schema::{Container, PropertySchema, TypeSchema};
use anyhow::{Context, Result, bail, ensure};
use ojak_jsonld::Registry;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// A value a property may hold that is not an object of another type.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Literal {
    /// `xsd:string`.
    String,
    /// `rdf:langString`: text, untagged or per language.
    LangString,
    /// `xsd:boolean`.
    Boolean,
    /// `xsd:nonNegativeInteger`.
    NonNegativeInteger,
    /// `xsd:float`.
    Float,
    /// `xsd:decimal`, kept as written so that no digit is lost.
    Decimal,
    /// `xsd:dateTime`, kept as written.
    DateTime,
    /// `xsd:duration`, kept as written.
    Duration,
    /// `xsd:anyURI`, `fedify:url`, and `fedify:gatewayUrl`, an FEP-ef61
    /// gateway origin, which `ojak::portable::is_gateway` checks.
    Iri,
    /// `fedify:langTag`: a BCP 47 language tag.
    LanguageTag,
    /// `fedify:publicKey`: an SPKI public key in PEM.
    PublicKeyPem,
    /// `fedify:multibaseKey`: a Multikey public key, multibase-encoded.
    MultibaseKey,
    /// `sec:multibase`: bytes, multibase-encoded, such as a proof's value.
    Multibase,
    /// `sec:cryptosuiteString`: the name of a Data Integrity cryptosuite.
    Cryptosuite,
    /// `fedify:proofPurpose`.
    ProofPurpose,
    /// `fedify:units`.
    Units,
    /// `fedify:vocabEntityType`: the IRI of a vocabulary type.
    TypeIri,
}

impl Literal {
    fn from_iri(iri: &str) -> Option<Self> {
        const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
        const RDF: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
        const SEC: &str = "https://w3id.org/security#";
        Some(match iri {
            _ if iri == format!("{XSD}string") => Self::String,
            _ if iri == format!("{RDF}langString") => Self::LangString,
            _ if iri == format!("{XSD}boolean") => Self::Boolean,
            _ if iri == format!("{XSD}nonNegativeInteger") => Self::NonNegativeInteger,
            _ if iri == format!("{XSD}float") => Self::Float,
            _ if iri == format!("{XSD}decimal") => Self::Decimal,
            _ if iri == format!("{XSD}dateTime") => Self::DateTime,
            _ if iri == format!("{XSD}duration") => Self::Duration,
            _ if iri == format!("{XSD}anyURI") => Self::Iri,
            _ if iri == format!("{SEC}multibase") => Self::Multibase,
            _ if iri == format!("{SEC}cryptosuiteString") => Self::Cryptosuite,
            "fedify:url" | "fedify:gatewayUrl" => Self::Iri,
            "fedify:langTag" => Self::LanguageTag,
            "fedify:publicKey" => Self::PublicKeyPem,
            "fedify:multibaseKey" => Self::MultibaseKey,
            "fedify:proofPurpose" => Self::ProofPurpose,
            "fedify:units" => Self::Units,
            "fedify:vocabEntityType" => Self::TypeIri,
            _ => return None,
        })
    }

    /// Whether a value of this kind is written as an IRI, so that a string in
    /// compact JSON-LD is ambiguous between it and a reference to an object.
    #[must_use]
    pub fn is_iri(self) -> bool {
        matches!(self, Self::Iri | Self::TypeIri)
    }
}

/// One of the things a property's values may be.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Range {
    Literal(Literal),
    /// Another type, by IRI.
    Type(String),
}

/// A hand-written Rust function that adjusts a value as it is read, standing
/// in for a TypeScript preprocessor the schema names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hook {
    /// A `Link` where an `Image` is expected is read as an `Image` of its
    /// `href`, which is what Misskey and others send for `icon` and `image`.
    LinkToImage,
}

impl Hook {
    fn from_function(function: &str) -> Option<Self> {
        match function {
            "normalizeLinkToImage" => Some(Self::LinkToImage),
            _ => None,
        }
    }
}

/// A property as generated Rust sees it.
#[derive(Clone, Debug)]
pub struct Property {
    pub uri: String,
    /// The Rust field name, snake case.
    pub field: String,
    /// The key in a normalised document.
    pub key: String,
    pub description: String,
    pub functional: bool,
    pub container: Option<Container>,
    /// Sorted, without duplicates.
    pub ranges: Vec<Range>,
    /// Keys of properties meaning the same, in the order they are tried.
    pub redundant_keys: Vec<String>,
    /// Keys the property is also read from, after the others, and never
    /// written to.
    pub fallback_keys: Vec<String>,
    pub hook: Option<Hook>,
    /// Whether the property's values are sent without a `type`.
    pub untyped: bool,
    /// The name of the type that declared the property.
    pub declared_by: String,
}

/// A type as generated Rust sees it.
#[derive(Clone, Debug)]
pub struct Type {
    pub name: String,
    pub uri: String,
    /// The value of `type` in a normalised document; `None` for a typeless
    /// type.
    pub type_term: Option<String>,
    pub entity: bool,
    pub description: String,
    pub parent: Option<String>,
    /// Every property, ancestors' first, each once. A property a type
    /// redeclares replaces its ancestor's in place.
    pub properties: Vec<Property>,
}

/// The whole vocabulary.
#[derive(Clone, Debug)]
pub struct Vocabulary {
    /// By IRI.
    pub types: BTreeMap<String, Type>,
}

impl Vocabulary {
    /// Work out the vocabulary from its schemas.
    ///
    /// # Errors
    ///
    /// When a schema names a type, range, or preprocessor that does not
    /// exist, or breaks a rule of the format.
    pub fn from_schemas(schemas: &[TypeSchema], registry: &Registry) -> Result<Self> {
        let by_uri: BTreeMap<&str, &TypeSchema> = schemas
            .iter()
            .map(|schema| (schema.uri.as_str(), schema))
            .collect();
        ensure!(by_uri.len() == schemas.len(), "two schemas share an IRI");
        let names: BTreeSet<&str> = schemas.iter().map(|schema| schema.name.as_str()).collect();
        ensure!(names.len() == schemas.len(), "two schemas share a name");

        let context = ojak_jsonld::ojak_context();
        let mut types = BTreeMap::new();
        for schema in schemas {
            let chain = ancestry(schema, &by_uri)?;
            let mut properties: Vec<Property> = Vec::new();
            for ancestor in chain.iter().rev() {
                for property in &ancestor.properties {
                    let property = analyse(property, ancestor, schema, &by_uri, registry, &context)
                        .with_context(|| format!("{}.{}", ancestor.name, property.singular_name))?;
                    match properties
                        .iter_mut()
                        .find(|known| known.uri == property.uri)
                    {
                        Some(known) => *known = property,
                        None => properties.push(property),
                    }
                }
            }
            let mut fields = BTreeSet::new();
            for property in &properties {
                ensure!(
                    fields.insert(property.field.as_str()),
                    "{} has two properties named {}",
                    schema.name,
                    property.field
                );
            }
            let type_term = if schema.typeless {
                None
            } else {
                Some(compact_type(&schema.uri, registry, &context)?)
            };
            types.insert(
                schema.uri.clone(),
                Type {
                    name: schema.name.clone(),
                    uri: schema.uri.clone(),
                    type_term,
                    entity: schema.entity,
                    description: schema.description.clone(),
                    parent: schema.extends.clone(),
                    properties,
                },
            );
        }
        Ok(Self { types })
    }

    /// The types that extend `uri`, directly or not, in IRI order.
    #[must_use]
    pub fn descendants(&self, uri: &str) -> Vec<&Type> {
        self.types
            .values()
            .filter(|candidate| {
                let mut parent = candidate.parent.as_deref();
                while let Some(ancestor) = parent {
                    if ancestor == uri {
                        return true;
                    }
                    parent = self.types.get(ancestor).and_then(|t| t.parent.as_deref());
                }
                false
            })
            .collect()
    }
}

/// `schema` and its ancestors, nearest first.
fn ancestry<'a>(
    schema: &'a TypeSchema,
    by_uri: &BTreeMap<&str, &'a TypeSchema>,
) -> Result<Vec<&'a TypeSchema>> {
    let mut chain = vec![schema];
    let mut next = schema.extends.as_deref();
    while let Some(uri) = next {
        let parent = by_uri
            .get(uri)
            .with_context(|| format!("{} extends unknown type {uri}", schema.name))?;
        ensure!(chain.len() < by_uri.len(), "{} extends itself", schema.name);
        chain.push(parent);
        next = parent.extends.as_deref();
    }
    Ok(chain)
}

fn analyse(
    property: &PropertySchema,
    declared_by: &TypeSchema,
    owner: &TypeSchema,
    by_uri: &BTreeMap<&str, &TypeSchema>,
    registry: &Registry,
    context: &Value,
) -> Result<Property> {
    if property.functional {
        ensure!(
            property.plural_name.is_none(),
            "a functional property has no plural name"
        );
    } else {
        ensure!(
            property.plural_name.is_some(),
            "a non-functional property needs a plural name"
        );
    }
    if property.untyped {
        ensure!(
            property.range.len() == 1,
            "an untyped property has one range"
        );
    }
    let mut ranges = BTreeSet::new();
    for iri in &property.range {
        let range = match Literal::from_iri(iri) {
            Some(literal) => Range::Literal(literal),
            None if by_uri.contains_key(iri.as_str()) => Range::Type(iri.clone()),
            None => bail!("unknown range {iri}"),
        };
        ranges.insert(range);
    }
    let hook = match property.preprocessors.as_slice() {
        [] => None,
        [preprocessor] => Some(
            Hook::from_function(&preprocessor.function).with_context(|| {
                format!(
                    "no Rust stand-in for the preprocessor {}",
                    preprocessor.function
                )
            })?,
        ),
        _ => bail!("more than one preprocessor"),
    };
    let takes_objects = ranges.iter().any(|range| {
        matches!(range, Range::Type(_)) || matches!(range, Range::Literal(l) if l.is_iri())
    });
    // Text in several languages is several JSON-LD values, so the schemas
    // call such a property plural. In Rust it is one `Text`, holding the
    // untagged value and one per language, and takes the singular name.
    let text_only = ranges.contains(&Range::Literal(Literal::LangString))
        && ranges
            .iter()
            .all(|range| matches!(range, Range::Literal(Literal::LangString | Literal::String)));
    let name = match &property.plural_name {
        Some(plural) if !text_only => plural,
        _ => &property.singular_name,
    };
    let owner_type = (!owner.typeless).then_some(owner.uri.as_str());
    let list = property.container == Some(Container::List);
    let key = compact_property(
        owner_type,
        &property.uri,
        takes_objects,
        list,
        registry,
        context,
    )?;
    let mut fallback_keys = Vec::new();
    // A list compacts to its own term, `orderedItems` for `as:items`; the
    // same property sent as a plain array compacts to the other, `items`, and
    // is read from there when the list is not sent. It is never written.
    if list {
        let plain = compact_property(
            owner_type,
            &property.uri,
            takes_objects,
            false,
            registry,
            context,
        )?;
        if plain != key {
            fallback_keys.push(plain);
        }
    }
    let mut redundant_keys = Vec::new();
    for redundant in &property.redundant_properties {
        redundant_keys.push(compact_property(
            owner_type,
            &redundant.uri,
            takes_objects,
            false,
            registry,
            context,
        )?);
    }
    Ok(Property {
        uri: property.uri.clone(),
        field: snake_case(name),
        key,
        description: property.description.clone(),
        functional: property.functional,
        container: property.container,
        ranges: ranges.into_iter().collect(),
        redundant_keys,
        fallback_keys,
        hook,
        untyped: property.untyped,
        declared_by: declared_by.name.clone(),
    })
}

/// The key `iri` has on an object of type `owner` once a document is
/// compacted into Ojak's context.
///
/// Worked out by compacting a one-property document rather than by looking
/// the IRI up in the context, so that it is the key `ojak_vocab::read`
/// produces by construction: a term defined with `"@type": "@id"` only
/// matches a reference, one without only a value, and a term a context
/// scopes to a type, as data-integrity's `proofValue` is scoped to
/// `DataIntegrityProof`, only applies on an object of that type.
fn compact_property(
    owner: Option<&str>,
    iri: &str,
    takes_objects: bool,
    list: bool,
    registry: &Registry,
    context: &Value,
) -> Result<String> {
    let sample = if takes_objects {
        json!({"@id": "https://ojak.example/sample"})
    } else {
        json!({"@value": "sample"})
    };
    let sample = if list {
        json!({ "@list": [sample] })
    } else {
        sample
    };
    let mut node = json!({ iri: [sample] });
    if let Some(owner) = owner {
        node["@type"] = json!([owner]);
    }
    let compacted = ojak_jsonld::compact(registry, &json!([node]), context)
        .map_err(|error| anyhow::anyhow!("compact {iri}: {error}"))?;
    let keys: Vec<&String> = compacted
        .document()
        .as_object()
        .context("compaction produced no object")?
        .keys()
        .filter(|key| !key.starts_with('@') && key.as_str() != "type")
        .collect();
    let [key] = keys.as_slice() else {
        bail!("compacting {iri} produced keys {keys:?}");
    };
    Ok((*key).clone())
}

/// The value of `type` for `iri` once compacted into Ojak's context.
fn compact_type(iri: &str, registry: &Registry, context: &Value) -> Result<String> {
    let expanded = json!([{ "@type": [iri] }]);
    let compacted = ojak_jsonld::compact(registry, &expanded, context)
        .map_err(|error| anyhow::anyhow!("compact type {iri}: {error}"))?;
    let document = compacted.document();
    let value = document
        .get("type")
        .or_else(|| document.get("@type"))
        .with_context(|| format!("compacting type {iri} produced {document}"))?;
    value
        .as_str()
        .map(str::to_owned)
        .with_context(|| format!("compacting type {iri} produced {value}"))
}

/// `camelCase` to `snake_case`.
#[must_use]
pub fn snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (index, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

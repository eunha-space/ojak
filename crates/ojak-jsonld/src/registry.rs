//! The set of JSON-LD contexts ojak can resolve.
//!
//! There is no document loader here, and that is the point. Context
//! resolution runs on inbound, attacker-controlled documents, before any
//! signature has been checked, so a loader that fetches the IRIs those
//! documents name is a request-forgery primitive reachable by anyone who can
//! post to an inbox. Ojak resolves what it ships and nothing else.
//!
//! See `contexts/README.md` for where each document came from and why.

use alloc::{
    borrow::ToOwned,
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use serde_json::Value;

/// A bundled context: the IRI documents refer to it by, and its JSON text.
struct Bundled {
    iri: &'static str,
    /// Extra IRIs that name the same document. Servers are inconsistent about
    /// the scheme and the trailing slash, and a near-miss would otherwise drop
    /// every term the document defines.
    aliases: &'static [&'static str],
    document: &'static str,
}

const BUNDLED: &[Bundled] = &[
    Bundled {
        iri: "https://www.w3.org/ns/activitystreams",
        aliases: &[
            "http://www.w3.org/ns/activitystreams",
            "https://www.w3.org/ns/activitystreams#",
        ],
        document: include_str!("../contexts/activitystreams.jsonld"),
    },
    Bundled {
        iri: "https://w3id.org/security/v1",
        aliases: &["http://w3id.org/security/v1"],
        document: include_str!("../contexts/security-v1.jsonld"),
    },
    // What a Linked Data Signature's options are read against. Its home,
    // web-payments.org, no longer answers; Mastodon ships a copy.
    Bundled {
        iri: "https://w3id.org/identity/v1",
        aliases: &["http://w3id.org/identity/v1"],
        document: include_str!("../contexts/identity-v1.jsonld"),
    },
    Bundled {
        iri: "https://w3id.org/security/data-integrity/v1",
        aliases: &[],
        document: include_str!("../contexts/security-data-integrity-v1.jsonld"),
    },
    Bundled {
        iri: "https://w3id.org/security/data-integrity/v2",
        // Where w3id.org redirects to.
        aliases: &["https://www.w3.org/2025/credentials/vcdi/context/v2.jsonld"],
        document: include_str!("../contexts/security-data-integrity-v2.jsonld"),
    },
    Bundled {
        iri: "https://w3id.org/security/multikey/v1",
        aliases: &[],
        document: include_str!("../contexts/security-multikey-v1.jsonld"),
    },
    Bundled {
        iri: "https://www.w3.org/ns/did/v1",
        aliases: &[],
        document: include_str!("../contexts/did-v1.jsonld"),
    },
    Bundled {
        iri: "https://www.w3.org/ns/cid/v1",
        aliases: &[],
        document: include_str!("../contexts/cid-v1.jsonld"),
    },
    Bundled {
        iri: "https://gotosocial.org/ns",
        aliases: &["https://gotosocial.org/ns#"],
        document: include_str!("../contexts/gotosocial.jsonld"),
    },
    Bundled {
        iri: "https://litepub.social/litepub/context.jsonld",
        aliases: &["http://litepub.social/litepub/context.jsonld"],
        document: include_str!("../contexts/litepub.jsonld"),
    },
    Bundled {
        iri: "https://purl.archive.org/socialweb/webfinger",
        aliases: &[],
        document: include_str!("../contexts/webfinger.jsonld"),
    },
    Bundled {
        iri: "https://w3id.org/fep/ef61",
        aliases: &[],
        document: include_str!("../contexts/fep-ef61.jsonld"),
    },
    Bundled {
        iri: "https://w3id.org/fep/7aa9",
        aliases: &[],
        document: include_str!("../contexts/fep-7aa9.jsonld"),
    },
    Bundled {
        iri: "https://w3id.org/fep/22cd",
        aliases: &[],
        document: include_str!("../contexts/fep-22cd.jsonld"),
    },
    // Served as `application/json` with no JSON-LD `Link` header, so a
    // conforming loader would not treat it as a context even after fetching it.
    Bundled {
        iri: "https://join-lemmy.org/context.json",
        aliases: &[],
        document: include_str!("../contexts/join-lemmy.jsonld"),
    },
    // Has never resolved; Mastodon inlines these terms instead. Bundled because
    // some implementations put the bare namespace IRI in `@context` anyway.
    Bundled {
        iri: "http://joinmastodon.org/ns",
        aliases: &["https://joinmastodon.org/ns", "http://joinmastodon.org/ns#"],
        document: include_str!("../contexts/joinmastodon.jsonld"),
    },
];

/// The contexts available to a processing run.
///
/// Parsing the bundled documents costs a few hundred microseconds, so build one
/// registry and keep it rather than building one per document.
#[derive(Clone, Debug)]
pub struct Registry {
    documents: BTreeMap<String, Value>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::bundled()
    }
}

impl Registry {
    /// Every context ojak ships, and nothing else.
    ///
    /// # Panics
    ///
    /// Never, for the bundled documents: they are parsed by a test.
    #[must_use]
    pub fn bundled() -> Self {
        let mut documents = BTreeMap::new();
        for entry in BUNDLED {
            let parsed: Value = serde_json::from_str(entry.document)
                .expect("bundled context document is valid JSON");
            for iri in core::iter::once(entry.iri).chain(entry.aliases.iter().copied()) {
                documents.insert(iri.to_owned(), parsed.clone());
            }
        }
        Self { documents }
    }

    /// An empty registry, resolving nothing.
    ///
    /// Useful for asking what a document means on its own terms: with no
    /// registry every `@context` IRI goes unresolved and only inline term
    /// definitions apply.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            documents: BTreeMap::new(),
        }
    }

    /// Add a context of the caller's own.
    ///
    /// The value is the whole context *document* — an object with an
    /// `@context` member — matching what the IRI would have served.
    #[must_use]
    pub fn with(mut self, iri: impl Into<String>, document: Value) -> Self {
        self.documents.insert(iri.into(), document);
        self
    }

    /// The `@context` member of the document registered under `iri`.
    pub(crate) fn resolve(&self, iri: &str) -> Option<&Value> {
        self.documents.get(iri).and_then(|doc| doc.get("@context"))
    }

    /// Every IRI this registry answers to, including aliases.
    #[must_use]
    pub fn known_iris(&self) -> Vec<String> {
        self.documents.keys().map(ToString::to_string).collect()
    }
}

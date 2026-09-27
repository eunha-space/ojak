//! Minimal Activity Vocabulary types for Feder.
#![no_std]
//!
//! This crate models ActivityPub/ActivityStreams protocol data only. It does
//! not fetch remote objects, read or write storage, deliver activities, or own
//! core decision logic.

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec, vec::Vec};
use iri_string::types::IriString;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    ser::{SerializeMap, SerializeSeq},
};

pub mod generated;
pub mod json;
mod read;

pub use read::{Read, ReadError, Registry, read, write};

/// The canonical Activity Streams JSON-LD context URL.
pub const ACTIVITYSTREAMS_CONTEXT: &str = "https://www.w3.org/ns/activitystreams";

/// The special collection addressing every actor (public posts).
pub const ACTIVITYSTREAMS_PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";

/// An absolute ActivityPub/ActivityStreams identifier.
pub type Iri = IriString;

/// Build the default top-level `@context` IRI value.
fn default_context() -> Iri {
    ACTIVITYSTREAMS_CONTEXT
        .parse()
        .expect("valid ActivityStreams IRI")
}

/// A consent-vocabulary term map appended to the base ActivityStreams context.
///
/// The FEP-044f quote and FEP-7aa9 feature handshakes introduce type IRIs
/// (`QuoteRequest`, `QuoteAuthorization`, …) and properties that the
/// ActivityStreams context does not define. A strict JSON-LD consumer (e.g.
/// Fedify, which backs hackers.pub / GoToSocial) expands `type: "QuoteRequest"`
/// against `@context`; without these definitions the term is dropped and the
/// activity is silently unrecognised. The term maps mirror Mastodon's
/// `context_helper` so quote requests are understood across implementations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContextExtension {
    QuoteRequest,
    FeatureRequest,
    QuoteAuthorization,
    FeatureAuthorization,
}

/// A top-level `@context` value. Serializes as the bare ActivityStreams IRI
/// string when there is no extension, or as `[as2_iri, { terms… }]` when a
/// consent vocabulary is attached.
///
/// It is written, never read. Which extension a document needs follows from
/// its `type`, so the consent types set it from that when they are
/// deserialized; what a sender's `@context` said has already been resolved by
/// [`read`] into the `type` itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    extension: Option<ContextExtension>,
}

impl Context {
    fn for_request(kind: RequestType) -> Self {
        Self {
            extension: Some(match kind {
                RequestType::QuoteRequest => ContextExtension::QuoteRequest,
                RequestType::FeatureRequest => ContextExtension::FeatureRequest,
            }),
        }
    }

    fn for_authorization(kind: AuthorizationType) -> Self {
        Self {
            extension: Some(match kind {
                AuthorizationType::QuoteAuthorization => ContextExtension::QuoteAuthorization,
                AuthorizationType::FeatureAuthorization => ContextExtension::FeatureAuthorization,
            }),
        }
    }
}

impl Serialize for Context {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.extension {
            None => serializer.serialize_str(ACTIVITYSTREAMS_CONTEXT),
            Some(extension) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(ACTIVITYSTREAMS_CONTEXT)?;
                seq.serialize_element(&ExtensionTerms(extension))?;
                seq.end()
            }
        }
    }
}

/// Serializes a [`ContextExtension`]'s term definitions as a JSON-LD map.
struct ExtensionTerms(ContextExtension);

impl Serialize for ExtensionTerms {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            ContextExtension::QuoteRequest => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("QuoteRequest", "https://w3id.org/fep/044f#QuoteRequest")?;
                map.end()
            }
            ContextExtension::FeatureRequest => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("FeatureRequest", "https://w3id.org/fep/7aa9#FeatureRequest")?;
                map.end()
            }
            ContextExtension::QuoteAuthorization => {
                let mut map = serializer.serialize_map(Some(4))?;
                map.serialize_entry("gts", "https://gotosocial.org/ns#")?;
                map.serialize_entry(
                    "QuoteAuthorization",
                    "https://w3id.org/fep/044f#QuoteAuthorization",
                )?;
                map.serialize_entry("interactingObject", &IdTyped("gts:interactingObject"))?;
                map.serialize_entry("interactionTarget", &IdTyped("gts:interactionTarget"))?;
                map.end()
            }
            ContextExtension::FeatureAuthorization => {
                let mut map = serializer.serialize_map(Some(4))?;
                map.serialize_entry("gts", "https://gotosocial.org/ns#")?;
                map.serialize_entry(
                    "FeatureAuthorization",
                    "https://w3id.org/fep/7aa9#FeatureAuthorization",
                )?;
                map.serialize_entry("interactingObject", &IdTyped("gts:interactingObject"))?;
                map.serialize_entry("interactionTarget", &IdTyped("gts:interactionTarget"))?;
                map.end()
            }
        }
    }
}

/// Serializes an IRI-typed JSON-LD term as `{ "@id": iri, "@type": "@id" }`.
struct IdTyped(&'static str);

impl Serialize for IdTyped {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("@id", self.0)?;
        map.serialize_entry("@type", "@id")?;
        map.end()
    }
}

/// A non-scalar ActivityStreams property value.
///
/// ActivityStreams object slots can contain either an embedded object or the
/// object's IRI. Feder keeps both forms explicit and avoids dereferencing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Reference<T> {
    Id(Iri),
    Object(Box<T>),
}

impl<T> Reference<T> {
    #[must_use]
    pub fn id(id: Iri) -> Self {
        Self::Id(id)
    }

    #[must_use]
    pub fn object(object: T) -> Self {
        Self::Object(Box::new(object))
    }
}

/// Zero or more ActivityStreams property values.
///
/// Use this with `#[serde(default, skip_serializing_if = "References::is_empty")]`
/// on containing fields. Empty values then serialize as absent, one value
/// serializes as a scalar, and multiple values serialize as an array.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct References<T> {
    values: Vec<T>,
}

impl<T> Default for References<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> References<T> {
    #[must_use]
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    #[must_use]
    pub fn one(value: T) -> Self {
        Self {
            values: Vec::from([value]),
        }
    }

    #[must_use]
    pub fn many(values: impl Into<Vec<T>>) -> Self {
        Self {
            values: values.into(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.values.iter()
    }

    pub fn into_vec(self) -> Vec<T> {
        self.values
    }
}

impl<T> From<Vec<T>> for References<T> {
    fn from(values: Vec<T>) -> Self {
        Self::many(values)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

/// Deserializes a property that may hold one value or several into a `Vec`.
///
/// JSON-LD does not distinguish `"x"` from `["x"]`, and compaction writes a
/// single value without the array, so a one-element `to` arrives as a string.
fn one_or_many<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(value) => vec![value],
        OneOrMany::Many(values) => values,
    })
}

/// A natural-language property as it may arrive: a plain string, a JSON-LD
/// value object, or an array of those.
///
/// A sender writes `content` and `contentMap` as two properties, but they are
/// one property to JSON-LD, and [`read`] hands them back merged under
/// `content`: the untagged value as a string and each tagged one as
/// `{"@value": …, "@language": …}`.
#[derive(Deserialize)]
#[serde(untagged)]
enum TextInput {
    Plain(String),
    Value {
        #[serde(rename = "@value")]
        value: String,
        #[serde(rename = "@language", default)]
        language: Option<String>,
    },
    Many(Vec<TextInput>),
}

/// Split a natural-language property into its untagged value and its values
/// per language, from either spelling of it.
fn split_text(
    input: Option<TextInput>,
    map: Option<BTreeMap<String, String>>,
) -> (Option<String>, BTreeMap<String, String>) {
    fn collect(
        input: TextInput,
        plain: &mut Option<String>,
        languages: &mut BTreeMap<String, String>,
    ) {
        match input {
            TextInput::Plain(value)
            | TextInput::Value {
                value,
                language: None,
            } => {
                plain.get_or_insert(value);
            }
            TextInput::Value {
                value,
                language: Some(language),
            } => {
                languages.entry(language).or_insert(value);
            }
            TextInput::Many(values) => {
                for value in values {
                    collect(value, plain, languages);
                }
            }
        }
    }

    let mut plain = None;
    let mut languages = map.unwrap_or_default();
    if let Some(input) = input {
        collect(input, &mut plain, &mut languages);
    }
    (plain, languages)
}

impl<T> Serialize for References<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.values.as_slice() {
            [] => {
                let sequence = serializer.serialize_seq(Some(0))?;
                sequence.end()
            }
            [value] => value.serialize(serializer),
            values => values.serialize(serializer),
        }
    }
}

impl<'de, T> Deserialize<'de> for References<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match OneOrMany::deserialize(deserializer)? {
            OneOrMany::One(value) => Ok(References::one(value)),
            OneOrMany::Many(values) => Ok(References::many(values)),
        }
    }
}

macro_rules! activitystreams_type {
    ($name:ident, $variant:ident) => {
        #[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
        pub enum $name {
            #[default]
            $variant,
        }
    };
}

activitystreams_type!(NoteType, Note);
activitystreams_type!(TombstoneType, Tombstone);
activitystreams_type!(FollowType, Follow);
activitystreams_type!(AcceptType, Accept);
activitystreams_type!(RejectType, Reject);
activitystreams_type!(CreateType, Create);
activitystreams_type!(UndoType, Undo);
activitystreams_type!(LikeType, Like);
activitystreams_type!(AnnounceType, Announce);
activitystreams_type!(BlockType, Block);
activitystreams_type!(DeleteType, Delete);
activitystreams_type!(UpdateType, Update);

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum ActorType {
    Application,
    Group,
    Organization,
    #[default]
    Person,
    Service,
}

/// A minimal ActivityPub actor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(from = "ActorFields")]
pub struct Actor {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Iri>,
    #[serde(rename = "type")]
    pub kind: ActorType,
    pub id: Iri,
    pub inbox: Iri,
    pub outbox: Iri,
    #[serde(rename = "preferredUsername", skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `name` per language, as `nameMap`.
    #[serde(rename = "nameMap", skip_serializing_if = "BTreeMap::is_empty")]
    pub name_map: BTreeMap<String, String>,
}

/// [`Actor`] as it is read, with `name` in either of its spellings.
#[derive(Deserialize)]
struct ActorFields {
    #[serde(rename = "@context", default)]
    context: Option<Iri>,
    #[serde(rename = "type")]
    kind: ActorType,
    id: Iri,
    inbox: Iri,
    outbox: Iri,
    #[serde(rename = "preferredUsername", default)]
    preferred_username: Option<String>,
    #[serde(default)]
    name: Option<TextInput>,
    #[serde(rename = "nameMap", default)]
    name_map: Option<BTreeMap<String, String>>,
}

impl From<ActorFields> for Actor {
    fn from(fields: ActorFields) -> Self {
        let (name, name_map) = split_text(fields.name, fields.name_map);
        Self {
            context: fields.context,
            kind: fields.kind,
            id: fields.id,
            inbox: fields.inbox,
            outbox: fields.outbox,
            preferred_username: fields.preferred_username,
            name,
            name_map,
        }
    }
}

impl Actor {
    #[must_use]
    pub fn person(id: Iri, inbox: Iri, outbox: Iri) -> Self {
        Self::new(ActorType::Person, id, inbox, outbox)
    }

    #[must_use]
    pub fn new(kind: ActorType, id: Iri, inbox: Iri, outbox: Iri) -> Self {
        Self {
            context: Some(
                ACTIVITYSTREAMS_CONTEXT
                    .parse()
                    .expect("valid ActivityStreams IRI"),
            ),
            kind,
            id,
            inbox,
            outbox,
            preferred_username: None,
            name: None,
            name_map: BTreeMap::new(),
        }
    }
}

/// A minimal ActivityStreams Note object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(from = "NoteFields")]
pub struct Note {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Iri>,
    #[serde(rename = "type")]
    pub kind: NoteType,
    pub id: Iri,
    #[serde(rename = "attributedTo", skip_serializing_if = "Option::is_none")]
    pub attributed_to: Option<Reference<Actor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// `summary` per language, as `summaryMap`.
    #[serde(rename = "summaryMap", skip_serializing_if = "BTreeMap::is_empty")]
    pub summary_map: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// `content` per language, as `contentMap`.
    #[serde(rename = "contentMap", skip_serializing_if = "BTreeMap::is_empty")]
    pub content_map: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    #[serde(rename = "inReplyTo", skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<Iri>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Iri>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<Iri>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<Iri>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
}

/// [`Note`] as it is read: natural-language properties in either spelling,
/// and addressing as one value or several.
#[derive(Deserialize)]
struct NoteFields {
    #[serde(rename = "@context", default)]
    context: Option<Iri>,
    #[serde(rename = "type")]
    kind: NoteType,
    id: Iri,
    #[serde(rename = "attributedTo", default)]
    attributed_to: Option<Reference<Actor>>,
    #[serde(default)]
    summary: Option<TextInput>,
    #[serde(rename = "summaryMap", default)]
    summary_map: Option<BTreeMap<String, String>>,
    #[serde(default)]
    content: Option<TextInput>,
    #[serde(rename = "contentMap", default)]
    content_map: Option<BTreeMap<String, String>>,
    #[serde(default)]
    sensitive: Option<bool>,
    #[serde(rename = "inReplyTo", default)]
    in_reply_to: Option<Iri>,
    #[serde(default)]
    url: Option<Iri>,
    #[serde(default, deserialize_with = "one_or_many")]
    to: Vec<Iri>,
    #[serde(default, deserialize_with = "one_or_many")]
    cc: Vec<Iri>,
    #[serde(default)]
    published: Option<String>,
}

impl From<NoteFields> for Note {
    fn from(fields: NoteFields) -> Self {
        let (summary, summary_map) = split_text(fields.summary, fields.summary_map);
        let (content, content_map) = split_text(fields.content, fields.content_map);
        Self {
            context: fields.context,
            kind: fields.kind,
            id: fields.id,
            attributed_to: fields.attributed_to,
            summary,
            summary_map,
            content,
            content_map,
            sensitive: fields.sensitive,
            in_reply_to: fields.in_reply_to,
            url: fields.url,
            to: fields.to,
            cc: fields.cc,
            published: fields.published,
        }
    }
}

impl Note {
    #[must_use]
    pub fn new(id: Iri) -> Self {
        Self {
            context: Some(default_context()),
            kind: NoteType::default(),
            id,
            attributed_to: None,
            summary: None,
            summary_map: BTreeMap::new(),
            content: None,
            content_map: BTreeMap::new(),
            sensitive: None,
            in_reply_to: None,
            url: None,
            to: Vec::new(),
            cc: Vec::new(),
            published: None,
        }
    }
}

/// A minimal Follow activity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Follow {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Iri>,
    #[serde(rename = "type")]
    pub kind: FollowType,
    pub id: Iri,
    pub actor: Reference<Actor>,
    pub object: Reference<Actor>,
}

impl Follow {
    #[must_use]
    pub fn new(id: Iri, actor: Reference<Actor>, object: Reference<Actor>) -> Self {
        Self {
            context: Some(
                ACTIVITYSTREAMS_CONTEXT
                    .parse()
                    .expect("valid ActivityStreams IRI"),
            ),
            kind: FollowType::default(),
            id,
            actor,
            object,
        }
    }
}

/// A minimal Accept activity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Accept {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Iri>,
    #[serde(rename = "type")]
    pub kind: AcceptType,
    pub id: Iri,
    pub actor: Reference<Actor>,
    pub object: Reference<Follow>,
}

impl Accept {
    #[must_use]
    pub fn new(id: Iri, actor: Reference<Actor>, object: Reference<Follow>) -> Self {
        Self {
            context: Some(
                ACTIVITYSTREAMS_CONTEXT
                    .parse()
                    .expect("valid ActivityStreams IRI"),
            ),
            kind: AcceptType::default(),
            id,
            actor,
            object,
        }
    }
}

/// A minimal Create activity for a concrete object type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Create<T> {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Iri>,
    #[serde(rename = "type")]
    pub kind: CreateType,
    pub id: Iri,
    pub actor: Reference<Actor>,
    #[serde(
        default,
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub to: Vec<Iri>,
    #[serde(
        default,
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub cc: Vec<Iri>,
    pub object: Reference<T>,
}

impl<T> Create<T> {
    #[must_use]
    pub fn new(id: Iri, actor: Reference<Actor>, object: Reference<T>) -> Self {
        Self {
            context: Some(default_context()),
            kind: CreateType::default(),
            id,
            actor,
            to: Vec::new(),
            cc: Vec::new(),
            object,
        }
    }
}

/// A `Reject` activity (e.g. declining a follow request).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Reject {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Iri>,
    #[serde(rename = "type")]
    pub kind: RejectType,
    pub id: Iri,
    pub actor: Reference<Actor>,
    pub object: Reference<Follow>,
}

impl Reject {
    #[must_use]
    pub fn new(id: Iri, actor: Reference<Actor>, object: Reference<Follow>) -> Self {
        Self {
            context: Some(default_context()),
            kind: RejectType::default(),
            id,
            actor,
            object,
        }
    }
}

/// A `Like` activity (favourite).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Like {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Iri>,
    #[serde(rename = "type")]
    pub kind: LikeType,
    pub id: Iri,
    pub actor: Reference<Actor>,
    pub object: Iri,
}

impl Like {
    #[must_use]
    pub fn new(id: Iri, actor: Reference<Actor>, object: Iri) -> Self {
        Self {
            context: Some(default_context()),
            kind: LikeType::default(),
            id,
            actor,
            object,
        }
    }
}

/// An `Announce` activity (boost/reblog).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Announce {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Iri>,
    #[serde(rename = "type")]
    pub kind: AnnounceType,
    pub id: Iri,
    pub actor: Reference<Actor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    #[serde(
        default,
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub to: Vec<Iri>,
    #[serde(
        default,
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub cc: Vec<Iri>,
    pub object: Iri,
}

impl Announce {
    #[must_use]
    pub fn new(id: Iri, actor: Reference<Actor>, object: Iri) -> Self {
        Self {
            context: Some(default_context()),
            kind: AnnounceType::default(),
            id,
            actor,
            published: None,
            to: Vec::new(),
            cc: Vec::new(),
            object,
        }
    }
}

/// A `Block` activity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Block {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Iri>,
    #[serde(rename = "type")]
    pub kind: BlockType,
    pub id: Iri,
    pub actor: Reference<Actor>,
    pub object: Iri,
}

impl Block {
    #[must_use]
    pub fn new(id: Iri, actor: Reference<Actor>, object: Iri) -> Self {
        Self {
            context: Some(default_context()),
            kind: BlockType::default(),
            id,
            actor,
            object,
        }
    }
}

/// A `Tombstone` object, used as the body of a [`Delete`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Tombstone {
    #[serde(rename = "type")]
    pub kind: TombstoneType,
    pub id: Iri,
}

impl Tombstone {
    #[must_use]
    pub fn new(id: Iri) -> Self {
        Self {
            kind: TombstoneType::default(),
            id,
        }
    }
}

/// A `Delete` activity for a removed object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Delete {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Iri>,
    #[serde(rename = "type")]
    pub kind: DeleteType,
    pub id: Iri,
    pub actor: Reference<Actor>,
    pub object: Tombstone,
}

impl Delete {
    #[must_use]
    pub fn new(id: Iri, actor: Reference<Actor>, object: Tombstone) -> Self {
        Self {
            context: Some(default_context()),
            kind: DeleteType::default(),
            id,
            actor,
            object,
        }
    }
}

/// An `Update` activity wrapping a changed object of type `T`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Update<T> {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Iri>,
    #[serde(rename = "type")]
    pub kind: UpdateType,
    pub id: Iri,
    pub actor: Reference<Actor>,
    #[serde(default, skip_serializing_if = "References::is_empty")]
    pub to: References<Iri>,
    pub object: T,
}

impl<T> Update<T> {
    #[must_use]
    pub fn new(id: Iri, actor: Reference<Actor>, object: T) -> Self {
        Self {
            context: Some(default_context()),
            kind: UpdateType::default(),
            id,
            actor,
            to: References::new(),
            object,
        }
    }
}

/// An `Undo` activity wrapping a previously-emitted activity of type `T`.
///
/// The wrapped `object` is embedded inline; callers should clear its own
/// `@context` (set `context` to `None`) before wrapping it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Undo<T> {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Iri>,
    #[serde(rename = "type")]
    pub kind: UndoType,
    pub id: Iri,
    pub actor: Reference<Actor>,
    pub object: T,
}

impl<T> Undo<T> {
    #[must_use]
    pub fn new(id: Iri, actor: Reference<Actor>, object: T) -> Self {
        Self {
            context: Some(default_context()),
            kind: UndoType::default(),
            id,
            actor,
            object,
        }
    }
}

// ── Consent handshake (FEP-style request / accept-with-result / reject) ────────
//
// A reusable pattern shared by interactions that need the target's consent:
// the requester sends a `Request`, the target replies with an `Accept` carrying
// a `result` authorization URI (a stamp the requester can reference and others
// can verify) or a `Reject`. Quote posts (`QuoteRequest` + `QuoteAuthorization`)
// and account features (`FeatureRequest` + `FeatureAuthorization`) are the two
// concrete uses.

/// The kind of consent being requested.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum RequestType {
    /// Request permission to quote a post (FEP-044f).
    #[default]
    QuoteRequest,
    /// Request permission to feature an account in a collection.
    FeatureRequest,
}

/// The kind of authorization stamp granted by an [`Accept`]'s `result`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthorizationType {
    /// Stamp proving a quote was authorized (FEP-044f).
    #[default]
    QuoteAuthorization,
    /// Stamp proving an account consented to being featured.
    FeatureAuthorization,
}

/// A consent request: the requester (`actor`) asks the owner of `object` for
/// permission to interact, where `instrument` is the requesting object (the
/// quote post, or the collection doing the featuring). `id` is the request's
/// own activity URI, later referenced by the [`ConsentAccept`]/[`ConsentReject`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(from = "ConsentRequestFields")]
pub struct ConsentRequest {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Context>,
    #[serde(rename = "type")]
    pub kind: RequestType,
    pub id: Iri,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<Reference<Actor>>,
    pub object: Iri,
    pub instrument: Iri,
}

/// [`ConsentRequest`] as it is read. Its `@context` follows from its `type`.
#[derive(Deserialize)]
struct ConsentRequestFields {
    #[serde(rename = "type")]
    kind: RequestType,
    id: Iri,
    #[serde(default)]
    actor: Option<Reference<Actor>>,
    object: Iri,
    instrument: Iri,
}

impl From<ConsentRequestFields> for ConsentRequest {
    fn from(fields: ConsentRequestFields) -> Self {
        Self {
            actor: fields.actor,
            ..Self::new(fields.kind, fields.id, fields.object, fields.instrument)
        }
    }
}

impl ConsentRequest {
    #[must_use]
    pub fn new(kind: RequestType, id: Iri, object: Iri, instrument: Iri) -> Self {
        Self {
            context: Some(Context::for_request(kind)),
            kind,
            id,
            actor: None,
            object,
            instrument,
        }
    }
}

/// An `Accept` granting a [`ConsentRequest`]. `object` is the request's URI and
/// `result` points to the [`Authorization`] stamp the granter published.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConsentAccept {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Iri>,
    #[serde(rename = "type")]
    pub kind: AcceptType,
    pub id: Iri,
    pub actor: Reference<Actor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Iri>,
    pub object: Iri,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Iri>,
}

impl ConsentAccept {
    #[must_use]
    pub fn new(id: Iri, actor: Reference<Actor>, object: Iri, result: Iri) -> Self {
        Self {
            context: Some(default_context()),
            kind: AcceptType::default(),
            id,
            actor,
            to: None,
            object,
            result: Some(result),
        }
    }
}

/// A `Reject` declining a [`ConsentRequest`]. `object` is the request's URI.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConsentReject {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Iri>,
    #[serde(rename = "type")]
    pub kind: RejectType,
    pub id: Iri,
    pub actor: Reference<Actor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Iri>,
    pub object: Iri,
}

impl ConsentReject {
    #[must_use]
    pub fn new(id: Iri, actor: Reference<Actor>, object: Iri) -> Self {
        Self {
            context: Some(default_context()),
            kind: RejectType::default(),
            id,
            actor,
            to: None,
            object,
        }
    }
}

/// An authorization stamp pointed to by a [`ConsentAccept`]'s `result`.
/// `interacting_object` is the requesting object (quote post / collection) and
/// `interaction_target` is the consented-to object (quoted status / account).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(from = "AuthorizationFields")]
pub struct Authorization {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Context>,
    #[serde(rename = "type")]
    pub kind: AuthorizationType,
    pub id: Iri,
    #[serde(rename = "attributedTo", skip_serializing_if = "Option::is_none")]
    pub attributed_to: Option<Reference<Actor>>,
    #[serde(rename = "interactingObject")]
    pub interacting_object: Iri,
    #[serde(rename = "interactionTarget")]
    pub interaction_target: Iri,
}

/// [`Authorization`] as it is read. Its `@context` follows from its `type`.
#[derive(Deserialize)]
struct AuthorizationFields {
    #[serde(rename = "type")]
    kind: AuthorizationType,
    id: Iri,
    #[serde(rename = "attributedTo", default)]
    attributed_to: Option<Reference<Actor>>,
    #[serde(rename = "interactingObject")]
    interacting_object: Iri,
    #[serde(rename = "interactionTarget")]
    interaction_target: Iri,
}

impl From<AuthorizationFields> for Authorization {
    fn from(fields: AuthorizationFields) -> Self {
        Self {
            attributed_to: fields.attributed_to,
            ..Self::new(
                fields.kind,
                fields.id,
                fields.interacting_object,
                fields.interaction_target,
            )
        }
    }
}

impl Authorization {
    #[must_use]
    pub fn new(
        kind: AuthorizationType,
        id: Iri,
        interacting_object: Iri,
        interaction_target: Iri,
    ) -> Self {
        Self {
            context: Some(Context::for_authorization(kind)),
            kind,
            id,
            attributed_to: None,
            interacting_object,
            interaction_target,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use serde::de::DeserializeOwned;
    use serde_json::json;

    fn roundtrip<T>(value: &T) -> T
    where
        T: DeserializeOwned + Serialize,
    {
        let json = serde_json::to_string(value).expect("serialize activitystreams value");
        serde_json::from_str(&json).expect("deserialize activitystreams value")
    }

    fn iri(value: &str) -> Iri {
        value.parse().expect("valid test IRI")
    }

    #[test]
    fn actor_roundtrips_json() {
        let mut actor = Actor::person(
            iri("https://example.com/users/alice"),
            iri("https://example.com/users/alice/inbox"),
            iri("https://example.com/users/alice/outbox"),
        );
        actor.preferred_username = Some("alice".to_string());
        actor.name = Some("Alice".to_string());

        assert_eq!(roundtrip(&actor), actor);
    }

    #[test]
    fn actor_deserializes_basic_activitypub_json() {
        let actor: Actor = serde_json::from_value(json!({
            "@context": ACTIVITYSTREAMS_CONTEXT,
            "type": "Person",
            "id": "https://example.com/users/alice",
            "inbox": "https://example.com/users/alice/inbox",
            "outbox": "https://example.com/users/alice/outbox",
            "preferredUsername": "alice",
            "name": "Alice"
        }))
        .expect("deserialize actor from json");

        assert_eq!(actor.id, iri("https://example.com/users/alice"));
        assert_eq!(actor.preferred_username, Some("alice".to_string()));
    }

    #[test]
    fn actor_deserializes_non_person_activitypub_json() {
        let actor: Actor = serde_json::from_value(json!({
            "@context": ACTIVITYSTREAMS_CONTEXT,
            "type": "Service",
            "id": "https://example.com/actors/service",
            "inbox": "https://example.com/actors/service/inbox",
            "outbox": "https://example.com/actors/service/outbox",
            "name": "Feder Service"
        }))
        .expect("deserialize service actor from json");

        assert_eq!(actor.kind, ActorType::Service);
        assert_eq!(actor.id, iri("https://example.com/actors/service"));
    }

    #[test]
    fn follow_and_accept_roundtrip_json() {
        let follow = Follow::new(
            iri("https://remote.example/activities/follow/1"),
            Reference::id(iri("https://remote.example/users/bob")),
            Reference::id(iri("https://example.com/users/alice")),
        );
        let accept = Accept::new(
            iri("https://example.com/activities/accept/1"),
            Reference::id(iri("https://example.com/users/alice")),
            Reference::object(follow),
        );

        assert_eq!(roundtrip(&accept), accept);
    }

    #[test]
    fn create_note_roundtrips_json() {
        let mut note = Note::new(iri("https://example.com/notes/1"));
        note.attributed_to = Some(Reference::id(iri("https://example.com/users/alice")));
        note.content = Some("Hello, fediverse.".to_string());
        note.published = Some("2026-05-29T06:30:00Z".to_string());

        let create = Create::new(
            iri("https://example.com/activities/create/1"),
            Reference::id(iri("https://example.com/users/alice")),
            Reference::object(note),
        );

        assert_eq!(roundtrip(&create), create);
    }

    #[test]
    fn like_block_delete_and_undo_shapes() {
        let like = Like::new(
            iri("https://example.com/activities/like/1"),
            Reference::id(iri("https://example.com/users/alice")),
            iri("https://remote.example/notes/9"),
        );
        assert_eq!(
            serde_json::to_value(&like).expect("serialize like"),
            json!({
                "@context": ACTIVITYSTREAMS_CONTEXT,
                "type": "Like",
                "id": "https://example.com/activities/like/1",
                "actor": "https://example.com/users/alice",
                "object": "https://remote.example/notes/9",
            })
        );

        let tombstone = Tombstone::new(iri("https://example.com/notes/1"));
        let delete = Delete::new(
            iri("https://example.com/notes/1#delete"),
            Reference::id(iri("https://example.com/users/alice")),
            tombstone,
        );
        assert_eq!(
            serde_json::to_value(&delete).expect("serialize delete")["object"],
            json!({ "type": "Tombstone", "id": "https://example.com/notes/1" })
        );
        assert_eq!(roundtrip(&delete), delete);

        // Undo embeds the wrapped activity without its own @context.
        let mut inner = Like::new(
            iri("https://example.com/activities/like/1"),
            Reference::id(iri("https://example.com/users/alice")),
            iri("https://remote.example/notes/9"),
        );
        inner.context = None;
        let undo = Undo::new(
            iri("https://example.com/activities/undo/1"),
            Reference::id(iri("https://example.com/users/alice")),
            inner,
        );
        let value = serde_json::to_value(&undo).expect("serialize undo");
        assert_eq!(value["type"], json!("Undo"));
        assert!(value["object"].get("@context").is_none());
        assert_eq!(value["object"]["type"], json!("Like"));
        assert_eq!(roundtrip(&undo), undo);
    }

    #[test]
    fn update_embeds_object_and_carries_audience() {
        let mut actor = Actor::person(
            iri("https://example.com/users/alice"),
            iri("https://example.com/users/alice/inbox"),
            iri("https://example.com/users/alice/outbox"),
        );
        actor.context = None;
        let mut update = Update::new(
            iri("https://example.com/users/alice#updates/1"),
            Reference::id(iri("https://example.com/users/alice")),
            actor,
        );
        update.to = References::one(iri(ACTIVITYSTREAMS_PUBLIC));

        let value = serde_json::to_value(&update).expect("serialize update");
        assert_eq!(value["type"], json!("Update"));
        assert_eq!(value["to"], json!(ACTIVITYSTREAMS_PUBLIC));
        assert_eq!(value["object"]["type"], json!("Person"));
        assert!(value["object"].get("@context").is_none());
        assert_eq!(roundtrip(&update), update);
    }

    #[test]
    fn announce_carries_audience_and_publish_time() {
        let mut announce = Announce::new(
            iri("https://example.com/activities/announce/1"),
            Reference::id(iri("https://example.com/users/alice")),
            iri("https://remote.example/notes/9"),
        );
        announce.published = Some("2026-05-29T06:30:00Z".to_string());
        announce.to = Vec::from([iri(ACTIVITYSTREAMS_PUBLIC)]);
        announce.cc = Vec::from([iri("https://example.com/users/alice/followers")]);
        assert_eq!(roundtrip(&announce), announce);
    }

    #[test]
    fn note_carries_mastodon_audience_fields() {
        let mut note = Note::new(iri("https://example.com/notes/1"));
        note.attributed_to = Some(Reference::id(iri("https://example.com/users/alice")));
        note.content = Some("Hello".to_string());
        note.sensitive = Some(false);
        note.url = Some(iri("https://example.com/@alice/1"));
        note.to = Vec::from([iri(ACTIVITYSTREAMS_PUBLIC)]);
        note.cc = Vec::from([iri("https://example.com/users/alice/followers")]);
        note.published = Some("2026-05-29T06:30:00Z".to_string());
        assert_eq!(roundtrip(&note), note);
    }

    #[test]
    fn consent_pattern_quote_and_feature_shapes() {
        // Quote request → accept-with-result, plus its authorization stamp.
        let mut req = ConsentRequest::new(
            RequestType::QuoteRequest,
            iri("https://a.test/users/alice/quote_requests/1"),
            iri("https://b.test/notes/9"),
            iri("https://a.test/notes/1"),
        );
        req.actor = Some(Reference::id(iri("https://a.test/users/alice")));
        let v = serde_json::to_value(&req).expect("serialize quote request");
        assert_eq!(v["type"], "QuoteRequest");
        assert_eq!(v["object"], "https://b.test/notes/9");
        assert_eq!(v["instrument"], "https://a.test/notes/1");
        assert_eq!(v["actor"], "https://a.test/users/alice");
        // The FEP-044f `QuoteRequest` type must be declared in `@context` or a
        // strict JSON-LD consumer drops the activity as unrecognised.
        assert_eq!(
            v["@context"],
            json!([
                "https://www.w3.org/ns/activitystreams",
                { "QuoteRequest": "https://w3id.org/fep/044f#QuoteRequest" }
            ])
        );
        assert_eq!(roundtrip(&req), req);

        let accept = ConsentAccept::new(
            iri("https://b.test/users/bob#accepts/quote_requests/1"),
            Reference::id(iri("https://b.test/users/bob")),
            iri("https://a.test/users/alice/quote_requests/1"),
            iri("https://b.test/notes/9/approvals/1"),
        );
        let av = serde_json::to_value(&accept).expect("serialize accept");
        assert_eq!(av["type"], "Accept");
        assert_eq!(av["object"], "https://a.test/users/alice/quote_requests/1");
        assert_eq!(av["result"], "https://b.test/notes/9/approvals/1");
        // `Accept` is a plain ActivityStreams type, so its context stays a bare
        // IRI (matching Mastodon's AcceptQuoteRequestSerializer).
        assert_eq!(av["@context"], "https://www.w3.org/ns/activitystreams");
        assert_eq!(roundtrip(&accept), accept);

        let mut stamp = Authorization::new(
            AuthorizationType::QuoteAuthorization,
            iri("https://b.test/notes/9/approvals/1"),
            iri("https://a.test/notes/1"),
            iri("https://b.test/notes/9"),
        );
        stamp.attributed_to = Some(Reference::id(iri("https://b.test/users/bob")));
        let sv = serde_json::to_value(&stamp).expect("serialize authorization");
        assert_eq!(sv["type"], "QuoteAuthorization");
        assert_eq!(sv["attributedTo"], "https://b.test/users/bob");
        assert_eq!(sv["interactingObject"], "https://a.test/notes/1");
        assert_eq!(sv["interactionTarget"], "https://b.test/notes/9");
        assert_eq!(
            sv["@context"],
            json!([
                "https://www.w3.org/ns/activitystreams",
                {
                    "gts": "https://gotosocial.org/ns#",
                    "QuoteAuthorization": "https://w3id.org/fep/044f#QuoteAuthorization",
                    "interactingObject": { "@id": "gts:interactingObject", "@type": "@id" },
                    "interactionTarget": { "@id": "gts:interactionTarget", "@type": "@id" }
                }
            ])
        );
        assert_eq!(roundtrip(&stamp), stamp);

        // Feature request reuses the same types with different markers; the
        // feature authorization omits attributedTo.
        let freq = ConsentRequest::new(
            RequestType::FeatureRequest,
            iri("https://a.test/users/alice/feature_requests/1"),
            iri("https://b.test/users/bob"),
            iri("https://a.test/collections/1"),
        );
        let freq_v = serde_json::to_value(&freq).expect("serialize feature request");
        assert_eq!(freq_v["type"], "FeatureRequest");
        assert_eq!(
            freq_v["@context"],
            json!([
                "https://www.w3.org/ns/activitystreams",
                { "FeatureRequest": "https://w3id.org/fep/7aa9#FeatureRequest" }
            ])
        );
        assert_eq!(roundtrip(&freq), freq);
        let fstamp = Authorization::new(
            AuthorizationType::FeatureAuthorization,
            iri("https://b.test/users/bob/feature_authorizations/1"),
            iri("https://a.test/collections/1"),
            iri("https://b.test/users/bob"),
        );
        let fv = serde_json::to_value(&fstamp).expect("serialize feature authorization");
        assert_eq!(fv["type"], "FeatureAuthorization");
        assert!(fv.get("attributedTo").is_none());
        assert_eq!(roundtrip(&fstamp), fstamp);

        let reject = ConsentReject::new(
            iri("https://b.test/users/bob#rejects/feature_requests/1"),
            Reference::id(iri("https://b.test/users/bob")),
            iri("https://a.test/users/alice/feature_requests/1"),
        );
        assert_eq!(
            serde_json::to_value(&reject).expect("serialize reject")["type"],
            "Reject"
        );
        assert_eq!(roundtrip(&reject), reject);
    }

    #[test]
    fn concrete_types_reject_wrong_activitystreams_type() {
        let result = serde_json::from_value::<Follow>(json!({
            "type": "Accept",
            "id": "https://remote.example/activities/follow/1",
            "actor": "https://remote.example/users/bob",
            "object": "https://example.com/users/alice"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn references_deserializes_scalar_and_array() {
        let one: References<Iri> = serde_json::from_value(json!("https://example.com/users/alice"))
            .expect("deserialize scalar references value");
        let many: References<Iri> = serde_json::from_value(json!([
            "https://example.com/users/alice",
            "https://example.com/users/bob"
        ]))
        .expect("deserialize array references value");

        assert_eq!(one, References::one(iri("https://example.com/users/alice")));
        assert_eq!(
            many,
            References::many([
                iri("https://example.com/users/alice"),
                iri("https://example.com/users/bob")
            ])
        );
    }

    #[test]
    fn references_serializes_empty_one_and_many() {
        assert_eq!(
            serde_json::to_value(References::<Iri>::new()).expect("serialize empty references"),
            json!([])
        );
        assert_eq!(
            serde_json::to_value(References::one(iri("https://example.com/users/alice")))
                .expect("serialize one reference"),
            json!("https://example.com/users/alice")
        );
        assert_eq!(
            serde_json::to_value(References::many([
                iri("https://example.com/users/alice"),
                iri("https://example.com/users/bob")
            ]))
            .expect("serialize many references"),
            json!([
                "https://example.com/users/alice",
                "https://example.com/users/bob"
            ])
        );
    }
}

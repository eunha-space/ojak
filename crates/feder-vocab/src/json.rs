//! Reading and writing the generated vocabulary types.
//!
//! The types in [`crate::generated`] are read from a normalised document, the
//! form [`crate::read`] produces, and written in the same spelling. Their
//! field-by-field code is generated; what it calls is here, written by hand.
//!
//! Reading is tolerant of values and strict about types. A property whose
//! value is not the shape its range allows is read as absent, because peers
//! send values nobody specified and one odd property should not cost the
//! whole object. An object whose `type` is not the one asked for is an error,
//! because reading a `Like` as a `Follow` is not tolerance.

use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use serde_json::{Map, Number, Value};

use crate::{Iri, Reference};

/// A value that can be read from a normalised document.
pub trait FromJson: Sized {
    /// Read `value`.
    ///
    /// # Errors
    ///
    /// When `value` is not a shape this type can be read from.
    fn from_json(value: &Value) -> Result<Self, JsonError>;
}

/// A value that can be written into a document in Feder's spelling.
pub trait ToJson {
    /// Write `self`.
    fn to_json(&self) -> Value;
}

/// Why a value could not be read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonError {
    message: String,
}

impl JsonError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::error::Error for JsonError {}

/// Natural-language text: a value in no particular language, and values per
/// language.
///
/// ActivityStreams writes these as two properties, `content` and
/// `contentMap`, and JSON-LD reads them as one; this is the one.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Text {
    /// The value with no language tag.
    pub value: Option<String>,
    /// Values by BCP 47 language tag.
    pub languages: BTreeMap<String, String>,
}

impl Text {
    /// Text with no language.
    #[must_use]
    pub fn plain(value: impl Into<String>) -> Self {
        Self {
            value: Some(value.into()),
            languages: BTreeMap::new(),
        }
    }

    /// Whether there is no text at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_none() && self.languages.is_empty()
    }

    fn collect(&mut self, value: &Value) {
        match value {
            Value::String(text) => {
                self.value.get_or_insert_with(|| text.clone());
            }
            Value::Object(object) => {
                let Some(Value::String(text)) = object.get("@value") else {
                    return;
                };
                match object.get("@language").and_then(Value::as_str) {
                    Some(language) => {
                        self.languages
                            .entry(language.to_owned())
                            .or_insert_with(|| text.clone());
                    }
                    None => {
                        self.value.get_or_insert_with(|| text.clone());
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    self.collect(value);
                }
            }
            _ => {}
        }
    }
}

/// A Data Integrity proof's purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofPurpose {
    AssertionMethod,
    Authentication,
    CapabilityInvocation,
    CapabilityDelegation,
    KeyAgreement,
}

impl ProofPurpose {
    const ALL: [(Self, &'static str); 5] = [
        (Self::AssertionMethod, "assertionMethod"),
        (Self::Authentication, "authentication"),
        (Self::CapabilityInvocation, "capabilityInvocation"),
        (Self::CapabilityDelegation, "capabilityDelegation"),
        (Self::KeyAgreement, "keyAgreement"),
    ];
}

impl FromJson for ProofPurpose {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let name = string(value)?;
        let name = name
            .strip_prefix("https://w3id.org/security#")
            .unwrap_or(name);
        Self::ALL
            .iter()
            .find(|(_, known)| *known == name)
            .map(|(purpose, _)| *purpose)
            .ok_or_else(|| JsonError::new(format!("unknown proof purpose {name}")))
    }
}

impl ToJson for ProofPurpose {
    fn to_json(&self) -> Value {
        let name = Self::ALL
            .iter()
            .find(|(purpose, _)| purpose == self)
            .map_or("", |(_, name)| name);
        Value::String(name.to_owned())
    }
}

/// A unit of length, as `Place.units` gives one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Units {
    Centimetres,
    Feet,
    Inches,
    Kilometres,
    Metres,
    Miles,
}

impl Units {
    const ALL: [(Self, &'static str); 6] = [
        (Self::Centimetres, "cm"),
        (Self::Feet, "feet"),
        (Self::Inches, "inches"),
        (Self::Kilometres, "km"),
        (Self::Metres, "m"),
        (Self::Miles, "miles"),
    ];
}

impl FromJson for Units {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let name = string(value)?;
        Self::ALL
            .iter()
            .find(|(_, known)| *known == name)
            .map(|(units, _)| *units)
            .ok_or_else(|| JsonError::new(format!("unknown units {name}")))
    }
}

impl ToJson for Units {
    fn to_json(&self) -> Value {
        let name = Self::ALL
            .iter()
            .find(|(units, _)| units == self)
            .map_or("", |(_, name)| name);
        Value::String(name.to_owned())
    }
}

/// The string a value holds, directly or as a JSON-LD value object.
fn string(value: &Value) -> Result<&str, JsonError> {
    match value {
        Value::String(text) => Ok(text),
        Value::Object(object) => match object.get("@value") {
            Some(Value::String(text)) => Ok(text),
            _ => Err(JsonError::new("expected a string")),
        },
        _ => Err(JsonError::new("expected a string")),
    }
}

/// The scalar a value holds, directly or as a JSON-LD value object.
fn scalar(value: &Value) -> &Value {
    match value {
        Value::Object(object) => object.get("@value").unwrap_or(value),
        other => other,
    }
}

impl FromJson for String {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        string(value).map(ToOwned::to_owned)
    }
}

impl ToJson for String {
    fn to_json(&self) -> Value {
        Value::String(self.clone())
    }
}

impl FromJson for bool {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        match scalar(value) {
            Value::Bool(flag) => Ok(*flag),
            Value::String(text) if text == "true" => Ok(true),
            Value::String(text) if text == "false" => Ok(false),
            _ => Err(JsonError::new("expected a boolean")),
        }
    }
}

impl ToJson for bool {
    fn to_json(&self) -> Value {
        Value::Bool(*self)
    }
}

impl FromJson for u64 {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        match scalar(value) {
            Value::Number(number) => number
                .as_u64()
                .ok_or_else(|| JsonError::new("expected a non-negative integer")),
            Value::String(text) => text
                .parse()
                .map_err(|_| JsonError::new("expected a non-negative integer")),
            _ => Err(JsonError::new("expected a non-negative integer")),
        }
    }
}

impl ToJson for u64 {
    fn to_json(&self) -> Value {
        Value::Number(Number::from(*self))
    }
}

impl FromJson for f64 {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        match scalar(value) {
            Value::Number(number) => number
                .as_f64()
                .ok_or_else(|| JsonError::new("expected a number")),
            Value::String(text) => text
                .parse()
                .map_err(|_| JsonError::new("expected a number")),
            _ => Err(JsonError::new("expected a number")),
        }
    }
}

impl ToJson for f64 {
    fn to_json(&self) -> Value {
        Number::from_f64(*self).map_or(Value::Null, Value::Number)
    }
}

impl FromJson for Iri {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let text = match value {
            // A reference written as a node, where the key has no `@id` type.
            Value::Object(object) if object.len() == 1 && object.contains_key("id") => {
                object["id"].as_str()
            }
            other => string(other).ok(),
        };
        text.ok_or_else(|| JsonError::new("expected an IRI"))?
            .parse()
            .map_err(|_| JsonError::new("not an IRI"))
    }
}

impl ToJson for Iri {
    fn to_json(&self) -> Value {
        Value::String(self.as_str().to_owned())
    }
}

impl<T: FromJson> FromJson for Box<T> {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        T::from_json(value).map(Box::new)
    }
}

impl<T: ToJson> ToJson for Box<T> {
    fn to_json(&self) -> Value {
        (**self).to_json()
    }
}

impl<T: FromJson> FromJson for Reference<T> {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        match value {
            Value::String(_) => Iri::from_json(value).map(Reference::Id),
            Value::Object(object) if object.len() == 1 && object.contains_key("id") => {
                Iri::from_json(value).map(Reference::Id)
            }
            _ => T::from_json(value).map(Reference::object),
        }
    }
}

impl<T: ToJson> ToJson for Reference<T> {
    fn to_json(&self) -> Value {
        match self {
            Reference::Id(id) => id.to_json(),
            Reference::Object(object) => object.to_json(),
        }
    }
}

/// `value` as an object.
///
/// # Errors
///
/// When it is not one.
pub fn object(value: &Value) -> Result<&Map<String, Value>, JsonError> {
    value
        .as_object()
        .ok_or_else(|| JsonError::new("expected an object"))
}

/// Whether `object`'s `type` is `expected`, alone or among several.
#[must_use]
pub fn has_type(object: &Map<String, Value>, expected: &str) -> bool {
    match object.get("type") {
        Some(Value::String(name)) => name == expected,
        Some(Value::Array(names)) => names.iter().any(|name| name.as_str() == Some(expected)),
        _ => false,
    }
}

/// Check that `object`'s `type` is `expected`.
///
/// # Errors
///
/// When it is absent or another type.
pub fn expect_type(object: &Map<String, Value>, expected: &str) -> Result<(), JsonError> {
    if has_type(object, expected) {
        Ok(())
    } else {
        Err(JsonError::new(format!(
            "expected type {expected}, found {}",
            object
                .get("type")
                .map_or_else(|| "none".to_string(), Value::to_string)
        )))
    }
}

/// `object`'s `id`.
#[must_use]
pub fn id(object: &Map<String, Value>) -> Option<Iri> {
    object.get("id").and_then(|id| Iri::from_json(id).ok())
}

/// The value under the first of `keys` present.
fn first_present<'a>(object: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

/// A property holding at most one value: the first of `keys` present, and
/// the first of its values that reads.
#[must_use]
pub fn one<T: FromJson>(object: &Map<String, Value>, keys: &[&str]) -> Option<T> {
    one_with(object, keys, T::from_json)
}

/// [`one`], reading each value with `read`.
#[must_use]
pub fn one_with<T>(
    object: &Map<String, Value>,
    keys: &[&str],
    read: fn(&Value) -> Result<T, JsonError>,
) -> Option<T> {
    match first_present(object, keys)? {
        Value::Array(values) => values.iter().find_map(|value| read(value).ok()),
        value => read(value).ok(),
    }
}

/// [`one`], with each value adjusted by `map` before it is read.
#[must_use]
pub fn one_mapped<T: FromJson>(
    object: &Map<String, Value>,
    keys: &[&str],
    map: fn(&Value) -> Value,
) -> Option<T> {
    match first_present(object, keys)? {
        Value::Array(values) => values
            .iter()
            .find_map(|value| T::from_json(&map(value)).ok()),
        value => T::from_json(&map(value)).ok(),
    }
}

/// A property that may hold several values: the first of `keys` present, and
/// every one of its values that reads.
#[must_use]
pub fn many<T: FromJson>(object: &Map<String, Value>, keys: &[&str]) -> Vec<T> {
    many_with(object, keys, T::from_json)
}

/// [`many`], reading each value with `read`.
#[must_use]
pub fn many_with<T>(
    object: &Map<String, Value>,
    keys: &[&str],
    read: fn(&Value) -> Result<T, JsonError>,
) -> Vec<T> {
    match first_present(object, keys) {
        Some(Value::Array(values)) => values.iter().filter_map(|value| read(value).ok()).collect(),
        Some(value) => read(value).ok().into_iter().collect(),
        None => Vec::new(),
    }
}

/// A reference, or an object read with `read`: how a property whose values
/// are sent without a `type` reads them.
///
/// # Errors
///
/// When the value is neither an IRI nor an object `read` accepts.
pub fn reference_with<T>(
    value: &Value,
    read: fn(&Value) -> Result<T, JsonError>,
) -> Result<Reference<T>, JsonError> {
    match value {
        Value::String(_) => Iri::from_json(value).map(Reference::Id),
        Value::Object(object) if object.len() == 1 && object.contains_key("id") => {
            Iri::from_json(value).map(Reference::Id)
        }
        _ => read(value).map(Reference::object),
    }
}

/// Write a reference, or an object with `write`.
pub fn write_reference<T>(reference: &Reference<T>, write: fn(&T) -> Value) -> Value {
    match reference {
        Reference::Id(id) => id.to_json(),
        Reference::Object(object) => write(object),
    }
}

/// `value` without its `type`, for a property whose values are sent without
/// one.
#[must_use]
pub fn without_type(mut value: Value) -> Value {
    if let Value::Object(object) = &mut value {
        object.remove("type");
    }
    value
}

/// [`many`], with each value adjusted by `map` before it is read.
#[must_use]
pub fn many_mapped<T: FromJson>(
    object: &Map<String, Value>,
    keys: &[&str],
    map: fn(&Value) -> Value,
) -> Vec<T> {
    match first_present(object, keys) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(|value| T::from_json(&map(value)).ok())
            .collect(),
        Some(value) => T::from_json(&map(value)).ok().into_iter().collect(),
        None => Vec::new(),
    }
}

/// A text property, under `key` in either of its spellings: merged, as a
/// normalised document has it, or split into `key` and `{key}Map`.
#[must_use]
pub fn text(object: &Map<String, Value>, key: &str) -> Text {
    let mut text = Text::default();
    if let Some(value) = object.get(key) {
        text.collect(value);
    }
    if let Some(Value::Object(map)) = object.get(&format!("{key}Map")) {
        for (language, value) in map {
            if let Value::String(value) = value {
                text.languages
                    .entry(language.clone())
                    .or_insert_with(|| value.clone());
            }
        }
    }
    text
}

/// Start writing an object.
#[must_use]
pub fn new_object(type_term: Option<&str>, id: Option<&Iri>) -> Map<String, Value> {
    let mut object = Map::new();
    if let Some(id) = id {
        object.insert("id".to_owned(), id.to_json());
    }
    if let Some(type_term) = type_term {
        object.insert("type".to_owned(), Value::String(type_term.to_owned()));
    }
    object
}

/// Write a property holding at most one value under each of `keys`.
pub fn put_one<T: ToJson>(object: &mut Map<String, Value>, keys: &[&str], value: Option<&T>) {
    put_one_with(object, keys, value, T::to_json);
}

/// [`put_one`], writing the value with `write`.
pub fn put_one_with<T>(
    object: &mut Map<String, Value>,
    keys: &[&str],
    value: Option<&T>,
    write: fn(&T) -> Value,
) {
    if let Some(value) = value {
        let value = write(value);
        for key in keys {
            object.insert((*key).to_owned(), value.clone());
        }
    }
}

/// Write a property that may hold several values under each of `keys`: one
/// value without an array, several with one, none not at all.
pub fn put_many<T: ToJson>(object: &mut Map<String, Value>, keys: &[&str], values: &[T]) {
    put_many_with(object, keys, values, T::to_json);
}

/// [`put_many`], writing each value with `write`.
pub fn put_many_with<T>(
    object: &mut Map<String, Value>,
    keys: &[&str],
    values: &[T],
    write: fn(&T) -> Value,
) {
    let value = match values {
        [] => return,
        [value] => write(value),
        values => Value::Array(values.iter().map(write).collect()),
    };
    for key in keys {
        object.insert((*key).to_owned(), value.clone());
    }
}

/// Write a text property as `key` and `{key}Map`, which is how peers that do
/// not process JSON-LD expect to find it.
pub fn put_text(object: &mut Map<String, Value>, key: &str, text: &Text) {
    if let Some(value) = &text.value {
        object.insert(key.to_owned(), Value::String(value.clone()));
    }
    if !text.languages.is_empty() {
        let map = text
            .languages
            .iter()
            .map(|(language, value)| (language.clone(), Value::String(value.clone())))
            .collect();
        object.insert(format!("{key}Map"), Value::Object(map));
    }
}

/// A `Link` where an `Image` is expected, read as an `Image` of its `href`.
///
/// Misskey and others send `icon` and `image` that way. Anything else is
/// passed through unchanged.
#[must_use]
pub fn link_to_image(value: &Value) -> Value {
    let Value::Object(object) = value else {
        return value.clone();
    };
    if !has_type(object, "Link") {
        return value.clone();
    }
    let Some(href) = object.get("href") else {
        return value.clone();
    };
    let mut image = Map::new();
    image.insert("type".to_owned(), Value::String("Image".to_owned()));
    image.insert("url".to_owned(), href.clone());
    for key in ["mediaType", "name", "width", "height"] {
        if let Some(field) = object.get(key) {
            image.insert(key.to_owned(), field.clone());
        }
    }
    Value::Object(image)
}

/// Implement `Serialize` and `Deserialize` through [`ToJson`] and
/// [`FromJson`].
macro_rules! serde_via_json {
    ($($name:ident),* $(,)?) => {$(
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serde::Serialize::serialize(&$crate::json::ToJson::to_json(self), serializer)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = <serde_json::Value as serde::Deserialize>::deserialize(deserializer)?;
                $crate::json::FromJson::from_json(&value).map_err(serde::de::Error::custom)
            }
        }
    )*};
}

pub(crate) use serde_via_json;

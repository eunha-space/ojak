//! The vocabulary schemas as they are written.
//!
//! Every struct here refuses keys it does not declare. The schemas' format is
//! Fedify's and can change under us; a key this generator does not know about
//! is a meaning it would otherwise silently drop from the generated types.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Map, Number, Value};
use std::path::Path;
use yaml_rust2::{Yaml, YamlLoader};

/// One type: an ActivityStreams class or an extension's.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TypeSchema {
    /// The path of the format schema, relative to Fedify's tree. Unused.
    #[serde(rename = "$schema")]
    pub format: String,
    /// The type's name, which the generated struct is named after.
    pub name: String,
    /// The name the type goes by in compact JSON-LD, when it has one.
    pub compact_name: Option<String>,
    /// The type's IRI.
    pub uri: String,
    /// The IRI of the type this one extends.
    pub extends: Option<String>,
    /// Whether the type is an entity, with an `id` of its own, rather than a
    /// value that only ever appears inside another object.
    pub entity: bool,
    pub description: String,
    /// The `@context` Fedify writes documents of this type with.
    pub default_context: Value,
    pub properties: Vec<PropertySchema>,
    /// Whether documents of this type carry no `type` at all.
    #[serde(default)]
    pub typeless: bool,
}

/// One property of a type.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PropertySchema {
    pub singular_name: String,
    /// The name for the property's values when it may hold several.
    pub plural_name: Option<String>,
    /// A TypeScript accessor hint. Unused.
    pub singular_accessor: Option<bool>,
    pub uri: String,
    pub compact_name: Option<String>,
    pub subproperty_of: Option<String>,
    pub description: String,
    /// Whether the property holds at most one value.
    #[serde(default)]
    pub functional: bool,
    /// The IRIs of the types the property's values may take.
    pub range: Vec<String>,
    /// Whether the property's values carry no `type`.
    #[serde(default)]
    pub untyped: bool,
    pub container: Option<Container>,
    /// Properties from other vocabularies that mean the same thing, read in
    /// order when this one is absent and written alongside it.
    #[serde(default)]
    pub redundant_properties: Vec<RedundantProperty>,
    /// Whether an embedded value keeps a `@context` of its own. Unused: every
    /// document Feder reads is normalised first, and embedded values lose
    /// theirs.
    pub embed_context: Option<Value>,
    /// TypeScript functions that adjust a value as it is read.
    #[serde(default)]
    pub preprocessors: Vec<Preprocessor>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Container {
    Graph,
    List,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RedundantProperty {
    pub uri: String,
    pub compact_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preprocessor {
    pub module: String,
    pub function: String,
}

/// Read every `*.yaml` schema in `dir`, sorted by file name.
///
/// # Errors
///
/// When a file cannot be read or parsed, or declares something this
/// generator does not know.
pub fn load_dir(dir: &Path) -> Result<Vec<TypeSchema>> {
    let mut paths = std::fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|path| path.extension().is_some_and(|ext| ext == "yaml"));
    paths.sort();
    paths
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;
            parse(&text).with_context(|| format!("parse {}", path.display()))
        })
        .collect()
}

/// Parse one schema.
///
/// # Errors
///
/// When the text is not one YAML document of the schema's shape.
pub fn parse(text: &str) -> Result<TypeSchema> {
    let documents = YamlLoader::load_from_str(text).context("YAML")?;
    let [document] = documents.as_slice() else {
        bail!("expected one YAML document, found {}", documents.len());
    };
    let value = to_json(document)?;
    serde_json::from_value(value).context("schema shape")
}

fn to_json(yaml: &Yaml) -> Result<Value> {
    Ok(match yaml {
        Yaml::String(s) => Value::String(s.clone()),
        Yaml::Boolean(b) => Value::Bool(*b),
        Yaml::Integer(i) => Value::Number(Number::from(*i)),
        Yaml::Real(r) => Value::Number(
            r.parse::<f64>()
                .ok()
                .and_then(Number::from_f64)
                .with_context(|| format!("number {r}"))?,
        ),
        Yaml::Null => Value::Null,
        Yaml::Array(items) => Value::Array(items.iter().map(to_json).collect::<Result<_>>()?),
        Yaml::Hash(entries) => {
            let mut map = Map::new();
            for (key, value) in entries {
                let Yaml::String(key) = key else {
                    bail!("mapping key {key:?} is not a string");
                };
                map.insert(key.clone(), to_json(value)?);
            }
            Value::Object(map)
        }
        other => bail!("unsupported YAML node {other:?}"),
    })
}

//! NodeInfo, 2.0 and 2.1, from one dispatcher.

use super::{Context, empty, response};
use http::{HeaderValue, StatusCode, header};
use serde_json::{Value, json};

pub(super) const LINKS_PATH: &str = "/.well-known/nodeinfo";
pub(super) const PATH_2_0: &str = "/nodeinfo/2.0";
pub(super) const PATH_2_1: &str = "/nodeinfo/2.1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Version {
    V2_0,
    V2_1,
}

impl Version {
    fn number(self) -> &'static str {
        match self {
            Self::V2_0 => "2.0",
            Self::V2_1 => "2.1",
        }
    }

    fn schema(self) -> String {
        format!(
            "http://nodeinfo.diaspora.software/ns/schema/{}",
            self.number()
        )
    }

    fn path(self) -> &'static str {
        match self {
            Self::V2_0 => PATH_2_0,
            Self::V2_1 => PATH_2_1,
        }
    }
}

/// The software a server runs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Software {
    /// Lower-case letters, digits and hyphens, as the schema requires.
    pub name: String,
    pub version: String,
    /// Only in 2.1.
    pub repository: Option<String>,
    /// Only in 2.1.
    pub homepage: Option<String>,
}

/// How much a server is used.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    pub users_total: Option<u64>,
    pub users_active_month: Option<u64>,
    pub users_active_halfyear: Option<u64>,
    pub local_posts: Option<u64>,
    pub local_comments: Option<u64>,
}

/// A server's NodeInfo, in the 2.1 schema; 2.0 is served from it without what
/// 2.0 lacks.
#[derive(Clone, Debug, PartialEq)]
pub struct NodeInfo {
    pub software: Software,
    /// `activitypub` unless the server speaks more.
    pub protocols: Vec<String>,
    pub inbound_services: Vec<String>,
    pub outbound_services: Vec<String>,
    pub open_registrations: bool,
    pub usage: Usage,
    /// Free-form, such as `nodeName` and `nodeDescription`.
    pub metadata: Value,
}

impl NodeInfo {
    /// A NodeInfo for `software`, speaking ActivityPub, closed to
    /// registrations, with nothing else said.
    #[must_use]
    pub fn new(software: Software) -> Self {
        Self {
            software,
            protocols: vec!["activitypub".to_owned()],
            inbound_services: Vec::new(),
            outbound_services: Vec::new(),
            open_registrations: false,
            usage: Usage::default(),
            metadata: json!({}),
        }
    }

    fn document(&self, version: Version) -> Value {
        let mut software = json!({
            "name": self.software.name,
            "version": self.software.version,
        });
        if version == Version::V2_1 {
            if let Some(repository) = &self.software.repository {
                software["repository"] = repository.as_str().into();
            }
            if let Some(homepage) = &self.software.homepage {
                software["homepage"] = homepage.as_str().into();
            }
        }
        let mut users = serde_json::Map::new();
        for (name, value) in [
            ("total", self.usage.users_total),
            ("activeMonth", self.usage.users_active_month),
            ("activeHalfyear", self.usage.users_active_halfyear),
        ] {
            if let Some(value) = value {
                users.insert(name.into(), value.into());
            }
        }
        let mut usage = json!({"users": users});
        if let Some(posts) = self.usage.local_posts {
            usage["localPosts"] = posts.into();
        }
        if let Some(comments) = self.usage.local_comments {
            usage["localComments"] = comments.into();
        }
        json!({
            "version": version.number(),
            "software": software,
            "protocols": self.protocols,
            "services": {"inbound": self.inbound_services, "outbound": self.outbound_services},
            "openRegistrations": self.open_registrations,
            "usage": usage,
            "metadata": self.metadata,
        })
    }
}

fn cors(mut response: http::Response<Vec<u8>>) -> http::Response<Vec<u8>> {
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

pub(super) fn links<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
) -> http::Response<Vec<u8>> {
    let links: Vec<Value> = [Version::V2_0, Version::V2_1]
        .into_iter()
        .map(|version| {
            let mut href = context.origin().clone();
            href.set_path(version.path());
            href.set_query(None);
            json!({"rel": version.schema(), "href": href.as_str()})
        })
        .collect();
    cors(response(
        StatusCode::OK,
        "application/json",
        serde_json::to_vec(&json!({"links": links})).unwrap_or_default(),
    ))
}

pub(super) async fn document<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    version: Version,
) -> http::Response<Vec<u8>> {
    let Some(nodeinfo) = &context.inner.federation.nodeinfo else {
        return empty(StatusCode::NOT_FOUND);
    };
    match nodeinfo(context.clone()).await {
        Ok(nodeinfo) => cors(response(
            StatusCode::OK,
            &format!("application/json; profile=\"{}#\"", version.schema()),
            serde_json::to_vec(&nodeinfo.document(version)).unwrap_or_default(),
        )),
        Err(error) => {
            context.report(&error);
            empty(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

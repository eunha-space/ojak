//! Serving a [`Federation`] from an axum application.
//!
//! [`wrap`] puts the federation in front of an application's router: a
//! request Ojak answers is answered, and every other one, including a
//! request to one of Ojak's routes that asked for a page rather than
//! ActivityPub, goes on to the application. An inbox's POST is read, up to
//! [`MAX_INBOX_BODY`], and received.
//!
//! ~~~~ ignore
//! let app = ojak_axum::wrap(app, federation, |parts| {
//!     parts.extensions.get::<AppState>().cloned()
//! });
//! ~~~~
//!
//! The function from the request's parts to the federation's data is where
//! an application with several tenants gives Ojak the one a request is for;
//! `None` sends the request to the application untouched.

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use ojak::federation::{Federation, Handled, MAX_INBOX_BODY};
use std::sync::Arc;

type DataFn<D> = Arc<dyn Fn(&Parts) -> Option<D> + Send + Sync>;

struct Serving<D> {
    federation: Federation<D>,
    data: DataFn<D>,
}

impl<D> Clone for Serving<D> {
    fn clone(&self) -> Self {
        Self {
            federation: self.federation.clone(),
            data: self.data.clone(),
        }
    }
}

/// `app`, with `federation` answering what is Ojak's. `app` is a router
/// with its state already given, as it would be served.
pub fn wrap<D>(
    app: Router,
    federation: Federation<D>,
    data: impl Fn(&Parts) -> Option<D> + Send + Sync + 'static,
) -> Router
where
    D: Clone + Send + Sync + 'static,
{
    let serving = Serving {
        federation,
        data: Arc::new(data),
    };
    // A router whose fallback is the application, so that the layer sees
    // every request, not only those the application routes.
    Router::new()
        .fallback_service(app)
        .layer(middleware::from_fn_with_state(serving, serve::<D>))
}

async fn serve<D: Clone + Send + Sync + 'static>(
    State(serving): State<Serving<D>>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let Some(data) = (serving.data)(&parts) else {
        return next.run(Request::from_parts(parts, body)).await;
    };
    if serving.federation.is_inbox(parts.uri.path()) {
        // An inbox's POST is read here, bounded, and the body is Ojak's.
        let Ok(body) = axum::body::to_bytes(body, MAX_INBOX_BODY).await else {
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        };
        return match serving
            .federation
            .handle_with_body(&parts, &body, data)
            .await
        {
            Handled::Response(response) => response.map(Body::from),
            _ => next.run(Request::from_parts(parts, Body::from(body))).await,
        };
    }
    match serving.federation.handle(&parts, data).await {
        Handled::Response(response) => response.map(Body::from),
        // A route of Ojak's that a browser asked for: the application's page
        // is at the same URL as an ActivityPub document, so a cache has to
        // keep the two apart by Accept.
        Handled::NotAcceptable => {
            let mut response = next.run(Request::from_parts(parts, body)).await;
            vary_on_accept(response.headers_mut());
            response
        }
        _ => next.run(Request::from_parts(parts, body)).await,
    }
}

/// Add `Accept` to `headers`' `Vary`, unless it is there already.
fn vary_on_accept(headers: &mut axum::http::HeaderMap) {
    let covered = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|name| name == "*" || name.eq_ignore_ascii_case("accept"));
    if !covered {
        headers.append(header::VARY, HeaderValue::from_static("Accept"));
    }
}

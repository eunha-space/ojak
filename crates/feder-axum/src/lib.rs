//! Serving a [`Federation`] from an axum application.
//!
//! [`wrap`] puts the federation in front of an application's router: a
//! request Feder answers is answered, and every other one, including a
//! request to one of Feder's routes that asked for a page rather than
//! ActivityPub, goes on to the application.
//!
//! ~~~~ ignore
//! let app = feder_axum::wrap(app, federation, |parts| {
//!     parts.extensions.get::<AppState>().cloned()
//! });
//! ~~~~
//!
//! The function from the request's parts to the federation's data is where
//! an application with several tenants gives Feder the one a request is for;
//! `None` sends the request to the application untouched.

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::middleware::{self, Next};
use axum::response::Response;
use feder::federation::{Federation, Handled};
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

/// `app`, with `federation` answering what is Feder's. `app` is a router
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
    if let Some(data) = (serving.data)(&parts)
        && let Handled::Response(response) = serving.federation.handle(&parts, data).await
    {
        return response.map(Body::from);
    }
    next.run(Request::from_parts(parts, body)).await
}

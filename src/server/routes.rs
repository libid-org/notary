//! The HTTP routes and the REST handlers.

use std::sync::atomic::Ordering;

use axum::{
    extract::State,
    http::StatusCode,
    response::{
        IntoResponse,
        Json,
        Response,
    },
    routing::get,
    Router,
};
use serde::Serialize;
use tower_http::cors::{
    Any,
    CorsLayer,
};

use super::{
    ws::{
        internal_notarize_proxy_ws_handler,
        notarize_proxy_ws_handler,
    },
    NotaryState,
    Tier,
};

#[derive(Serialize)]
struct InfoResponse {
    version: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}

/// The HTTP routes. With `internal_proxy_route` the internal ProxyMode
/// route is mounted beside the public one; without it that path is a 404
/// like any other.
pub(super) fn router(notary: NotaryState, internal_proxy_route: bool) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(Any);
    let mut router = Router::new()
        .route("/info", get(info_handler))
        .route("/healthcheck", get(healthcheck_handler))
        .route(Tier::Public.route(), get(notarize_proxy_ws_handler));
    if internal_proxy_route {
        router = router.route(
            Tier::Internal.route(),
            get(internal_notarize_proxy_ws_handler),
        );
    }
    router.layer(cors).with_state(notary)
}

async fn info_handler(State(state): State<NotaryState>) -> Json<InfoResponse> {
    Json(InfoResponse {
        version: format!("v{}", env!("CARGO_PKG_VERSION")),
        public_key: state.public_key_hex.clone(),
    })
}

/// `{"status":"ok"}`, or 503 `{"status":"draining"}` once the process has
/// been told to stop, so the balancer takes this replica out before its
/// listeners close.
async fn healthcheck_handler(State(state): State<NotaryState>) -> Response {
    if state.draining.load(Ordering::SeqCst) {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "draining" })),
        )
            .into_response()
    } else {
        Json(serde_json::json!({ "status": "ok" })).into_response()
    }
}

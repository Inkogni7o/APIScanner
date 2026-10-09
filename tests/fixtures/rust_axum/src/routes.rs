use axum::{Router, routing::get};
use crate::handlers::{run, read, proxy, safe};

pub fn router() -> Router {
    Router::new()
        .route("/run", get(run))
        .route("/files/{name}", get(read))
        .route("/proxy", get(proxy))
        .route("/safe", get(safe))
}

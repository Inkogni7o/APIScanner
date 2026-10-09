use axum::{extract::Query, routing::get, Router};
use std::collections::HashMap;

async fn lookup(Query(params): Query<HashMap<String, String>>) -> String {
    let name = &params["name"];
    let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap();
    let query = sqlx::query(&format!("SELECT name FROM users WHERE name = '{}'", name));
    format!("{:?}", query)
}

pub fn app() -> Router {
    Router::new().route("/rust/sql", get(lookup))
}

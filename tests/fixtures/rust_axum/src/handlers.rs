use axum::extract::{Query, Path};
use tokio::process::Command;

#[derive(serde::Deserialize)]
pub struct Input { pub command: String, pub url: String }

pub async fn run(Query(input): Query<Input>) -> String {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(&input.command);
    format!("{:?}", cmd.output().await)
}

pub async fn read(Path(name): Path<String>) -> String {
    std::fs::read_to_string(format!("/srv/files/{}", name)).unwrap()
}

pub async fn proxy(Query(input): Query<Input>) -> String {
    reqwest::get(&input.url).await.unwrap().text().await.unwrap()
}

pub async fn safe(Query(input): Query<Input>) -> String {
    let output = Command::new("echo").arg(&input.command).output().await;
    format!("{:?}", output)
}

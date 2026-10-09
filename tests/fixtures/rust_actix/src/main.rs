use actix_web::{get, web, App, HttpRequest, HttpServer};
use std::process::Command;

#[get("/run")]
async fn run(req: HttpRequest) -> String {
    format!("{:?}", Command::new("sh").arg("-c").arg(req.query_string()).output())
}

async fn read(name: web::Path<String>) -> String {
    std::fs::read_to_string(name.into_inner()).unwrap()
}

fn main() {
    let server = HttpServer::new(|| App::new().service(
        web::scope("/api").service(run).route("/files/{name}", web::get().to(read))
    ));
}

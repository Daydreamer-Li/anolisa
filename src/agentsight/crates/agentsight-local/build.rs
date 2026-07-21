use std::env;
use std::path::PathBuf;

fn ensure_frontend_dist() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set");
    let frontend_dist = PathBuf::from(&manifest_dir).join("frontend-dist");
    if !frontend_dist.exists() {
        std::fs::create_dir_all(&frontend_dist).expect("Failed to create frontend-dist directory");
    }
    println!("cargo:rerun-if-changed=frontend-dist");
    if let Ok(entries) = std::fs::read_dir(&frontend_dist) {
        for entry in entries.flatten() {
            println!("cargo:rerun-if-changed={}", entry.path().display());
        }
    }
}

fn main() {
    ensure_frontend_dist();
}

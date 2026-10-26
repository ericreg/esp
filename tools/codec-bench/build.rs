use std::process::Command;
fn main() {
    let version = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .arg("--version")
        .output()
        .expect("rustc version");
    println!(
        "cargo:rustc-env=BENCH_RUSTC={}",
        String::from_utf8_lossy(&version.stdout).trim()
    );
    println!(
        "cargo:rustc-env=BENCH_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
    println!(
        "cargo:rustc-env=BENCH_PROFILE={}",
        std::env::var("PROFILE").unwrap()
    );
    println!(
        "cargo:rustc-env=BENCH_RUSTFLAGS={}",
        std::env::var("CARGO_ENCODED_RUSTFLAGS")
            .unwrap_or_default()
            .replace('\u{1f}', " ")
    );
    println!("cargo:rerun-if-changed=build.rs");
}

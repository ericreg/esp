fn main() {
    println!("cargo:rerun-if-changed=src/video/vpx.c");
    if std::env::var_os("CARGO_FEATURE_VIDEO_CODEC").is_none() {
        return;
    }
    let vpx = pkg_config::Config::new()
        .atleast_version("1.16.0")
        .probe("vpx")
        .expect("video-codec requires libvpx >= 1.16.0 development files; see drivers/esp_video/README.md");
    let mut build = cc::Build::new();
    build.file("src/video/vpx.c").warnings(true);
    for include in vpx.include_paths {
        build.include(include);
    }
    build.compile("esp_vpx");
}

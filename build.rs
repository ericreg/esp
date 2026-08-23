fn main() {
    println!("cargo:rerun-if-changed=schema/esp.capnp");

    let request = capnpc_embedded::CompileCommand::new()
        .src_prefix("schema")
        .file("schema/esp.capnp")
        .compile()
        .expect("failed to compile Cap'n Proto schema");

    capnpc::codegen::CodeGenerationCommand::new()
        .output_directory(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo"))
        .run(&request[..])
        .expect("failed to generate Cap'n Proto Rust code");
}

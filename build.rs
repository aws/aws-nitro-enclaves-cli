extern crate bindgen;

use std::path::PathBuf;

const HEADER_PATH: &str = "include/uapi/linux/nitro_enclaves.h";
const OUT_PATH: &str = "src/bindings/mod.rs";

fn main() {
    println!("{}", format!("cargo:rerun-if-changed={}", HEADER_PATH));

    let bindings = bindgen::Builder::default()
        .raw_line("#![allow(missing_docs)]")
        .header(HEADER_PATH)
        .whitelist_type("enclave_start_metadata")
        .clang_arg(r"-fretain-comments-from-system-headers")
        .clang_arg(r"-fparse-all-comments")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate_comments(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(OUT_PATH);
    bindings
        .write_to_file(out_path)
        .expect("Could not write bindings");
}

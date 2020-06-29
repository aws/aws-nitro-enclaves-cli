extern crate bindgen;

use std::path::PathBuf;

const HEADER_PATH: &str = "include/uapi/linux/nitro_enclaves.h";
const OUT_FILE: &str = "/driver-structs.rs";

fn main() {
    println!("{}", format!("cargo:rerun-if-changed={}", HEADER_PATH));

    let bindings = bindgen::Builder::default()
        .header(HEADER_PATH)
        .whitelist_type("enclave_start_metadata")
        .clang_arg(r"-fretain-comments-from-system-headers")
        .clang_arg(r"-fparse-all-comments")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate_comments(true)
        .generate()
        .expect("Unable to generate bindings");

    let mut path_str = std::env::var("OUT_DIR").unwrap();
    path_str.push_str(&OUT_FILE);
    let out_path = PathBuf::from(path_str);
    bindings
        .write_to_file(out_path)
        .expect("Could not write bindings");
}

extern crate bindgen;

use std::path::PathBuf;
use std::process::Command;

const HEADER_PATH: &str = "include/uapi/linux/nitro_enclaves.h";
const OUT_FILE: &str = "/driver_structs.rs";

fn main() {
    // Get latest commit SHA.
    let output = Command::new("git")
        .arg("describe")
        .arg("--always")
        .arg("--dirty")
        .output();

    // Convert command output to latest commit SHA and set an environment
    // variable ("COMMIT_ID", only available in the build context) to
    // the aforementioned commit SHA.
    let stdout;
    let output_str: &str = match output {
        Ok(output) => {
            stdout = output.stdout;
            std::str::from_utf8(&stdout).expect("Invalid UTF-8 string provided")
        }
        _ => "",
    };

    println!("cargo:rustc-env=COMMIT_ID={}", output_str.trim());
    println!("cargo:rerun-if-changed={}", HEADER_PATH);

    let bindings = bindgen::Builder::default()
        .header(HEADER_PATH)
        .whitelist_type("ne_.*")
        .whitelist_var("NE_ERR_.*")
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

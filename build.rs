extern crate bindgen;

use std::env;
use std::io;
use std::path::PathBuf;
use std::process::Command;

const HEADER_PATH: &str = "include/uapi/linux/nitro_enclaves.h";
const OUT_FILE: &str = "/driver_structs.rs";

// Generate the sysroot path based on the architecture the program is built.
// This is needed for the compiler to locate the architecture dependent
// header files.
fn get_gcc_sysroot() -> String {
    // Initialize the output because it might remain uninitialized with the
    // current control flow
    let mut output = Err(io::Error::from(io::ErrorKind::NotFound));

    // Use the `CC` environment variable if existing
    // which should give us directly the compiler's name
    let cc = env::var("CC");
    if let Ok(cc) = cc {
        output = Command::new(cc).arg("--print-sysroot").output();
    }

    if let Err(_) = output {
        // Otherwise, try to guess the compiler's name by the name
        // $TARGET-gcc, where $TARGET represents the target architecture
        // that was specified for build
        let target = env::var("TARGET").unwrap();
        output = Command::new(format!("{}-gcc", target))
            .arg("--print-sysroot")
            .output();
        if let Err(_) = output {
            // If that did not work as well, use directly `gcc`
            output = Command::new("gcc").arg("--print-sysroot").output();
        }
    }

    // At this point we should have a valid command output
    // that gives us the sysroot path
    let output = output.expect("no compiler was found for the current target");
    let output = String::from_utf8_lossy(&output.stdout);
    let path = output.trim().to_string();
    println!("cargo:rerun-if-changed={}", path);
    path
}

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
        .clang_arg(format!("--sysroot={}", get_gcc_sysroot()))
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

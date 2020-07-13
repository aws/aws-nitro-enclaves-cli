use std::process::Command;

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
}

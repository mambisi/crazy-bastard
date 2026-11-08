use std::{env, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=src/code/monitor_probe.c");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        _ => panic!("unsupported macOS architecture"),
    };
    assert!(
        Command::new("/usr/bin/clang")
            .args([
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-O2",
                "-arch",
                arch,
                "-c",
                "src/code/monitor_probe.c",
                "-o"
            ])
            .arg(out.join("probe.o"))
            .status()
            .expect("Apple command line tools are required")
            .success(),
        "monitor SDK shim compilation failed"
    );
    assert!(
        Command::new("/usr/bin/ar")
            .arg("crs")
            .arg(out.join("libcb_monitor_probe.a"))
            .arg(out.join("probe.o"))
            .status()
            .expect("Apple ar is required")
            .success(),
        "monitor SDK shim archive failed"
    );
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=cb_monitor_probe");
}

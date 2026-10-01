// build.rs — link libpam without requiring libpam-dev (same approach as
// lion-greeter). The vendored FFI in src/pam_ffi.rs needs no bindgen,
// no libclang, and no dev headers; this script only tells the linker
// where libpam lives, preferring the unversioned dev symlink but
// falling back to the runtime-only `libpam.so.0` that every PAM-using
// Linux box already has.

use std::path::PathBuf;

fn main() {
    let candidates: Vec<PathBuf> = common_lib_dirs()
        .iter()
        .map(|d| PathBuf::from(d).join("libpam.so"))
        .collect();

    if candidates.iter().any(|p| p.exists()) {
        println!("cargo:rustc-link-lib=dylib=pam");
    } else {
        // GNU ld `:` syntax: link to a file named exactly `libpam.so.0`.
        println!("cargo:rustc-link-arg=-l:libpam.so.0");
    }

    println!("cargo:rerun-if-changed=build.rs");
}

fn common_lib_dirs() -> &'static [&'static str] {
    &[
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/lib",
        "/lib64",
        "/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu",
    ]
}

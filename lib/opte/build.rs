fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo::rustc-check-cfg=cfg(usdt_stable_asm)");
    println!("cargo::rustc-check-cfg=cfg(usdt_stable_asm_sym)");

    if version_check::is_min_version("1.59").unwrap_or(false) {
        println!("cargo:rustc-cfg=usdt_stable_asm");
    }

    #[cfg(target_os = "macos")]
    if version_check::is_min_version("1.66").unwrap_or(false) {
        println!("cargo:rustc-cfg=usdt_stable_asm_sym");
    }
}

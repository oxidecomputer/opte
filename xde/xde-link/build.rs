fn main() {
    // Match linker flags used with other devfsadm plugins.
    //
    // DYNFLAGS = $(HSONAME) $(ZTEXT) $(ZDEFS) $(BDIRECT) \
    //      $(MAPFILES:%=-Wl,-M%) $(MAPFILE.PGA:%=-Wl,-M%) $(MAPFILE.NED:%=-Wl,-M%) \
    //      $(LDCHECKS)
    //
    // See:
    // - usr/src/Makefile.master
    // - usr/src/lib/Makefile.lib
    // - usr/src/cmd/devfsadm/Makefile.com

    // $(HSONAME)
    println!("cargo:rustc-cdylib-link-arg=-Wl,-hSUNW_xde_link.so");

    // $(ZTEXT) $(ZDEFS) $(BDIRECT)
    println!("cargo:rustc-cdylib-link-arg=-Wl,-ztext");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-zdefs");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-Bdirect");

    // $(MAPFILES)
    //
    // We reference symbols that exist only within devfsadm itself and
    // can only be resolved at runtime. At link time though it remains
    // unresolved and -zdefs thus forces an error. We suppress the error
    // by explicitly telling the linker that these symbols are external
    // via a mapfile (map.devfsadm-externs).
    //
    // See usr/src/cmd/devfsadm/mapfile-vers
    println!(
        "cargo:rustc-cdylib-link-arg=-Wl,-M{}/map.devfsadm-externs",
        env!("CARGO_MANIFEST_DIR"),
    );

    // $(MAPFILE.PGA) $(MAPFILE.NED)
    println!("cargo:rustc-cdylib-link-arg=-Wl,-M/usr/lib/ld/map.pagealign");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-M/usr/lib/ld/map.noexdata");

    // LDCHECKS = $(ZASSERTDEFLIB) $(ZGUIDANCE) $(ZFATALWARNINGS)
    println!("cargo:rustc-cdylib-link-arg=-Wl,-zassert-deflib");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-zguidance");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-zfatal-warnings");

    // We're linking against libc and libdevinfo and relying on the linker
    // finding them in /lib. Unfortunately, the linker will also complain
    // about this (and subsequently fail due to -zfatal-warnings):
    //
    //  ld: warning: dynamic library found on default search path (/lib): libdevinfo.so
    //  ld: warning: dynamic library found on default search path (/lib): libc.so
    //
    // The in-gate devfsadm plugins don't have this problem because they always
    // link against libs in the workspace proto area and not the default search path.
    // Just explicitly suppress the warning for these two libs.
    println!("cargo:rustc-cdylib-link-arg=-Wl,-zassert-deflib=libc.so");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-zassert-deflib=libdevinfo.so");
}

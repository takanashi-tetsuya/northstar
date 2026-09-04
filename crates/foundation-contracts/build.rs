//! Build-time guard for the repository-authoritative Buf output.
//!
//! Contract generation is intentionally performed by the pinned Buf workflow
//! and checked into this crate.  The build script does not silently regenerate
//! code with a developer's local `protoc`; it only fails when the expected
//! generated modules are absent and asks Cargo to rebuild when the source
//! schemas change.

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=../../contracts/proto");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let generated_dir = manifest_dir.join("src/generated");
    for module in [
        "mod.rs",
        "northstar.common.v1.rs",
        "northstar.identity.v1.rs",
        "northstar.identity.v1.tonic.rs",
        "northstar.session.v1.rs",
        "northstar.session.v1.tonic.rs",
        "northstar.ingress.v1.rs",
        "northstar.ingress.v1.tonic.rs",
        "northstar.delivery.v1.rs",
        "northstar.delivery.v1.tonic.rs",
        "northstar.registry.v1.rs",
        "northstar.registry.v1.tonic.rs",
        "northstar.events.v1.rs",
        "northstar.security.v1.rs",
    ] {
        let path = generated_dir.join(module);
        let contents = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "missing generated contract module {}: {error}",
                path.display()
            )
        });
        if module != "mod.rs" && !contents.contains("@generated") {
            panic!(
                "generated contract module is missing its generated marker: {}",
                path.display()
            );
        }
    }
}

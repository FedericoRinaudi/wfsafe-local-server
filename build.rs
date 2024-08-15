use std::env;
use libbpf_cargo::SkeletonBuilder;
use std::path::PathBuf;

const SRC: &str = "src/ebpf/wfsafe.bpf.c";

/*
fn main() {
    let mut out =
        PathBuf::from("src/ebpf");

    out.push("wfsafe.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .unwrap();

    println!("cargo:rerun-if-changed={SRC}");
}*/

fn main() {
    let mut out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    ).join("src/ebpf");
    out.push("wfsafe.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}

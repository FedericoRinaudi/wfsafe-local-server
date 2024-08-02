use libbpf_cargo::SkeletonBuilder;
use std::{path::PathBuf};

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

    let mut out =
        PathBuf::from("src/ebpf");
    out.push("wfsafe.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}

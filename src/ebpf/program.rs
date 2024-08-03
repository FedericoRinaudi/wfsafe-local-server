use crate::ebpf::error::EbpfError;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use rlimit::{setrlimit, Resource};

mod wfsafe {
    include!("./wfsafe.skel.rs");
}

use wfsafe::*;
use crate::ebpf::clients_map::ClientsMap;

pub struct EbpfProgram;

impl EbpfProgram {
    pub fn run() -> Result<ClientsMap, EbpfError> {
        setrlimit(Resource::MEMLOCK, u64::MAX, u64::MAX).unwrap();

        let skel_builder = WfsafeSkelBuilder::default();
        let open_skel = skel_builder.open()?;
        let mut skel = open_skel.load()?;
        let mut prog = skel.progs_mut();
        let link = prog.xdp_parser_func().attach_xdp(1)?;
        let map_name = skel.maps().clients_map().name().to_string();
        let object = skel.obj;

        Ok(ClientsMap::new(link, map_name, object))
    }
}
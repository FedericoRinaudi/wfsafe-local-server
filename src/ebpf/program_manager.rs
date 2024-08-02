use libbpf_rs::{Link, MapFlags};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use crate::ebpf::error::EbpfError;

mod wfsafe {
    include!("./wfsafe.skel.rs");
}

use wfsafe::*;
use crate::entities::flow::Flow;
use crate::entities::keys::Keys;
pub struct EbpfProgramManager {
    link: Link,
    client_map_accessor: ClientMapAccessor
}

impl EbpfProgramManager {
    pub fn run_program() -> Result<EbpfProgramManager, EbpfError> {

        rlimit::setrlimit(rlimit::Resource::MEMLOCK, u64::MAX, u64::MAX).unwrap();

        let skel_builder = WfsafeSkelBuilder::default();
        let open_skel = skel_builder.open()?;
        let mut skel: WfsafeSkel = open_skel.load()?;
        let mut prog = skel.progs_mut();
        let link = prog.xdp_parser_func().attach_xdp(1)?;
        let map_name = skel.maps().clients_map().name().to_string();
        let object = skel.obj;

        Ok(Self{
            link,
            client_map_accessor: ClientMapAccessor{
                map_name,
                object
            }
        })
    }

    pub fn get_client_map_accessor(&self) -> &ClientMapAccessor {
        &self.client_map_accessor
    }

}

impl Drop for EbpfProgramManager {
    fn drop(&mut self) {
        self.link.detach().unwrap();
    }
}

unsafe impl Send for EbpfProgramManager {}
unsafe impl Sync for EbpfProgramManager {}

struct ClientMapAccessor {
    map_name: String,
    object: libbpf_rs::Object,
}

impl ClientMapAccessor {
    pub fn insert(&mut self, key: &Keys, flow: &Flow) -> Result<(), EbpfError> {
        let map = self.object.map_mut(&self.map_name).ok_or(EbpfError::Err(format!("Map \"{}\" not found", &self.map_name)))?;
        map.update(key, flow, MapFlags::ANY)?;
        Ok(())
    }
}

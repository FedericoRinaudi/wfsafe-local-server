use libbpf_rs::{Link, MapFlags, Object};
use crate::ebpf::error::EbpfError;
use crate::entities::flow::Flow;
use crate::entities::keys::Keys;

pub struct ClientsMap {
    link: Link,
    map_name: String,
    object: Object,
}

impl ClientsMap {
    pub fn new(link: Link, map_name: String, object: Object) -> Self {
        ClientsMap {
            link,
            map_name,
            object,
        }
    }
    
    pub fn insert(&mut self, flow: &Flow, keys: &Keys) -> Result<(), EbpfError> {
        let map = self
            .object
            .map_mut(&self.map_name)
            .ok_or(EbpfError::Err(format!(
                "Map \"{}\" not found",
                &self.map_name
            )))?;
        map.update(flow, keys, MapFlags::ANY)?;
        Ok(())
    }

    pub fn delete(&mut self, flow: &Flow) -> Result<(), EbpfError> {
        let map = self
            .object
            .map_mut(&self.map_name)
            .ok_or(EbpfError::Err(format!(
                "Map \"{}\" not found",
                &self.map_name
            )))?;
        map.delete(flow)?;
        Ok(())
    }
}

unsafe impl Send for ClientsMap {}
unsafe impl Sync for ClientsMap {}

impl Drop for ClientsMap {
    fn drop(&mut self) {
        self.link.detach().unwrap();
        let map = self.object.map_mut(&self.map_name).ok_or(EbpfError::Err(format!("Map \"{}\" not found", &self.map_name))).unwrap();
        let keys :Vec<Vec<u8>> = map.keys().into_iter().collect();
        let count = keys.len() as u32;
        if  count !=0 {
            let batch: Vec<u8> = keys.into_iter().flatten().collect();
            map.delete_batch(&batch, count, MapFlags::ANY, MapFlags::ANY).unwrap();
        }
        }
}
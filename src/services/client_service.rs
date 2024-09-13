use crate::dtos::client::ClientDTO;
use crate::dtos::flow::FlowDTO;
use crate::ebpf::clients_map::ClientsMap;
use crate::ebpf::error::EbpfError;

pub struct ClientService;

impl ClientService {
    pub fn register_client(
        clients_map: &mut ClientsMap,
        client_dto: ClientDTO,
    ) -> Result<(), EbpfError> {
        let flow = client_dto.flow.into();
        let keys = client_dto.keys.into();
        clients_map.insert(&flow, &keys)
    }

    pub fn unregister_client(
        clients_map: &mut ClientsMap,
        flow_dto: FlowDTO,
    ) -> Result<(), EbpfError> {
        let flow = flow_dto.into();
        clients_map.delete(&flow)
    }
}

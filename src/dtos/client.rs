use crate::dtos::flow::{validate_flow, FlowDTO};
use crate::dtos::keys::KeysDTO;
use crate::impl_from_data;
use rocket::serde::Deserialize;

//TODO: vedo se aggiungere stats di default da cui partire a calcolare media e varianza o se hardocarle nel db
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct ClientDTO {
    pub flow: FlowDTO,
    pub keys: KeysDTO,
}

pub fn validate_client(client: &ClientDTO) -> Result<(), String> {
    validate_flow(&client.flow)?;
    Ok(())
}

impl_from_data!(ClientDTO, validate_client);

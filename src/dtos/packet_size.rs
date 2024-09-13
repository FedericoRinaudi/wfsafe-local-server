use crate::impl_from_data;
use rocket::serde::Deserialize;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct PacketSizeDTO {
    pub(crate) size: usize,
}

fn validate_packet_size(packet_size: &PacketSizeDTO) -> Result<(), String> {
    if packet_size.size == 0 {
        return Err("Invalid packet size".to_string());
    }
    Ok(())
}

impl_from_data!(PacketSizeDTO, validate_packet_size);

use rocket::serde::Deserialize;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct KeysDTO {
    padding_key: [u8; 32],
    dummy_packet_key: [u8; 32],
}

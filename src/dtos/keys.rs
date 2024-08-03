use crate::entities::keys::Keys;
use rocket::serde::Deserialize;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct KeysDTO {
    padding_key: [u8; 32],
    dummy_packet_key: [u8; 32],
}

impl Into<Keys> for KeysDTO {
    fn into(self) -> Keys {
        Keys::new(self.padding_key, self.dummy_packet_key)
    }
}

use rocket::serde::Deserialize;
use crate::impl_from_data;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub(crate) struct NumberOfPacketsDTO {
    number: usize,
}

fn validate_number_of_packets(number_of_packets: &NumberOfPacketsDTO) -> Result<(), String> {
    if number_of_packets.number == 0 {
        return Err("Invalid number of packets".to_string());
    }
    Ok(())
}

impl_from_data!(NumberOfPacketsDTO, validate_number_of_packets);
use rocket::serde::{ Deserialize };
use crate::dtos::utilities::{impl_from_data, validate_ip};

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct FlowDTO {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
}

pub fn validate_flow(flow: &FlowDTO) -> Result<(), String> {
    if validate_ip(&flow.src_ip).is_err() {
        return Err("Invalid source IP address".to_string());
    }
    if validate_ip(&flow.dst_ip).is_err() {
        return Err("Invalid destination IP address".to_string());
    }
    Ok(())
}

impl_from_data!(FlowDTO, validate_flow);
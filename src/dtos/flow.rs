use crate::dtos::utilities::validate_ip;
use crate::entities::flow::Flow;
use crate::parse_ip_to_u32;
use crate::impl_from_data;
use rocket::serde::Deserialize;
use std::net::Ipv4Addr;

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

impl Into<Flow> for FlowDTO {
    fn into(self) -> Flow {
        Flow::new(
            parse_ip_to_u32!(self.src_ip),
            parse_ip_to_u32!(self.dst_ip),
            self.src_port,
            self.dst_port,
        )
    }
}

#[macro_use]
extern crate rocket;

mod dtos;
mod ebpf;
mod services;
mod entities;

use rocket::response::status::{Accepted, BadRequest, Created};
use rocket::serde::json::Json;
use crate::dtos::stats::StatsDTO;
use crate::dtos::flow::FlowDTO;
use crate::dtos::packet_stats::PacketStatsDTO;
use crate::dtos::client::ClientDTO;
use crate::dtos::packet_size::PacketSizeDTO;
use crate::dtos::packet_number::NumberOfPacketsDTO;
use crate::ebpf::program_manager::EbpfProgramManager;

#[get("/<protocol_name>/stats")]
async fn stats(protocol_name: &str) -> Result<Accepted<Json<PacketStatsDTO>>, BadRequest<String>> {
    if protocol_name != "odoh" {
        return Err(BadRequest(format!("Protocol {} not found", protocol_name)));
    }
    // TODO: implement stats calculation
    Ok(Accepted(Json(PacketStatsDTO::new(
        StatsDTO::new(100, 10),
        StatsDTO::new(20, 5),
    ))))
}

#[post("/<protocol_name>/client", format = "json", data = "<client>")]
async fn register_client(protocol_name: &str, client: ClientDTO) -> Result<Created<()>, BadRequest<String>> {
    println!("Registering client for protocol {}", protocol_name);
    //TODO: implement client registration,
    // and adding it to the map of clients
    Ok(Created::new(""))
}
#[delete("/<protocol_name>/client", format = "json", data = "<flow>")]
async fn unregister_client(protocol_name: &str, flow: FlowDTO) -> Result<Created<()>, BadRequest<String>> {
    //TODO: implement client unregistration, removing a protocol if needed
    // and removing it from the map of clients
    println!("Unregistering client for protocol {}", protocol_name);
    Ok(Created::new(""))
}

#[post("/<protocol_name>/packet/size", format = "json", data = "<packet_size>")]
async fn register_packet_size(protocol_name: &str, packet_size: PacketSizeDTO) -> Result<Created<()>, BadRequest<String>> {
    println!("Registering packet size for protocol {}", protocol_name);
    Ok(Created::new(""))
}
#[post("/<protocol_name>/packet/number", format = "json", data = "<number_of_packets>")]
async fn register_packet_number(protocol_name: &str, number_of_packets: NumberOfPacketsDTO) -> Result<Created<()>, BadRequest<String>> {
    println!("Registering packet number for protocol {}", protocol_name);
    Ok(Created::new(""))
}

#[launch]
fn rocket() -> _ {
    let ebpf_program_manager = EbpfProgramManager::run_program().unwrap_or_else(|e| {
        panic!("Error running eBPF program: {}", e);
    });
    rocket::build()
        .manage(ebpf_program_manager)
        .mount("/", routes![
            stats,
            register_client,
            register_packet_size,
            register_packet_number,
            unregister_client
        ])
}

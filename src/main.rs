#[macro_use]
extern crate rocket;

mod dtos;
mod ebpf;
mod entities;
mod services;

use std::sync::Mutex;
use crate::dtos::client::ClientDTO;
use crate::dtos::flow::FlowDTO;
use crate::dtos::packet_number::NumberOfPacketsDTO;
use crate::dtos::packet_size::PacketSizeDTO;
use crate::dtos::packet_stats::PacketStatsDTO;
use crate::dtos::stats::StatsDTO;
use crate::ebpf::program::EbpfProgram;
use rocket::response::status::{Accepted, BadRequest, Created};
use rocket::serde::json::Json;
use crate::services::client_service::ClientService;
use crate::ebpf::clients_map::ClientsMap;
use rocket::State;

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

#[post("/client", format = "json", data = "<client>")]
async fn register_client(
    client: ClientDTO,
    clients_map: &State<Mutex<ClientsMap>>,

) -> Result<Created<()>, BadRequest<String>> {
    let mut  clients_map = clients_map.lock().expect("Failed to lock mutex");
    ClientService::register_client(&mut clients_map, client).map_err(|e| {
        BadRequest(format!("Error registering client: {}", e))
    })?;
    Ok(Created::new(""))
}

#[delete("/client", format = "json", data = "<flow>")]
async fn unregister_client(
    flow: FlowDTO,
    clients_map: &State<Mutex<ClientsMap>>,

) -> Result<Created<()>, BadRequest<String>> {
    let mut  clients_map = clients_map.lock().expect("Failed to lock mutex");
    ClientService::unregister_client(&mut clients_map, flow).map_err(|e| {
        BadRequest(format!("Error unregistering client: {}", e))
    })?;
    Ok(Created::new(""))
}

#[post(
    "/<protocol_name>/packet/size",
    format = "json",
    data = "<packet_size>"
)]
async fn register_packet_size(
    protocol_name: &str,
    packet_size: PacketSizeDTO,
) -> Result<Created<()>, BadRequest<String>> {
    println!("Registering packet size for protocol {}", protocol_name);
    Ok(Created::new(""))
}
#[post(
    "/<protocol_name>/packet/number",
    format = "json",
    data = "<number_of_packets>"
)]
async fn register_packet_number(
    protocol_name: &str,
    number_of_packets: NumberOfPacketsDTO,
) -> Result<Created<()>, BadRequest<String>> {
    println!("Registering packet number for protocol {}", protocol_name);
    Ok(Created::new(""))
}

#[launch]
fn rocket() -> _ {
    let clients_map = EbpfProgram::run().unwrap_or_else(|e| {
        panic!("Error running eBPF program: {}", e);
    });
    rocket::build()
        .manage(Mutex::new(clients_map))
        .mount(
        "/",
        routes![
            stats,
            register_client,
            register_packet_size,
            register_packet_number,
            unregister_client
        ],
    )
}

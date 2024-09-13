#[macro_use]
extern crate rocket;

mod db;
mod dtos;
mod ebpf;
mod entities;
mod services;
mod schema;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use crate::dtos::client::ClientDTO;
use crate::dtos::flow::FlowDTO;
use crate::dtos::packet_number::NumberOfPacketsDTO;
use crate::dtos::packet_size::PacketSizeDTO;
use crate::dtos::packet_stats::PacketStatsDTO;
use crate::dtos::stats::StatsDTO;
use crate::ebpf::clients_map::ClientsMap;
use crate::ebpf::program::EbpfProgram;
use crate::services::client_service::ClientService;
use rocket::response::status::{Accepted, BadRequest, Created};
use rocket::serde::json::Json;
use rocket::State;
use rocket_db_pools::{Database, diesel::AsyncPgConnection, Connection};
use rocket::tokio::sync::Mutex;
use diesel::associations::HasTable;
use diesel::RunQueryDsl;
use rocket::fairing::AdHoc;
use rocket::serde::{Deserialize, Serialize};
use rocket_db_pools::diesel::{Insertable, IntoSql, PgPool, prelude::*, Queryable, Selectable};
use crate::entities::stats::Stats;
use crate::protocols::{connection_n, packets_n};

const PACKET_SIZE_STATS_BATCH_SIZE: usize = 100;
const PACKET_NUMBER_STATS_BATCH_SIZE: usize = 10;

#[derive(Database)]
#[database("db")]
struct Db(PgPool);

#[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable, AsChangeset)]
#[serde(crate = "rocket::serde")]
#[diesel(table_name = protocols)]
struct Protocol {
    name: String,
    packets_n: i32,
    connection_n: i32,
    sum_of_packets_size: i32,
    sum_of_packets_per_connection: i32,
    sum_of_squares_of_packets_size: i32,
    sum_of_squares_of_packets_per_connection: i32,
}

table! {
    protocols (name) {
        #[max_length = 255]
        name -> Varchar,
        packets_n -> Int4,
        connection_n -> Int4,
        sum_of_packets_size -> Int4,
        sum_of_packets_per_connection -> Int4,
        sum_of_squares_of_packets_size -> Int4,
        sum_of_squares_of_packets_per_connection -> Int4,
    }
}

struct PacketSizeBatch {
    protocols: HashMap<String, Stats>
}

struct PacketNumberBatch {
    protocols: HashMap<String, Stats>
}


#[get("/<protocol_name>/stats")]
async fn stats(protocol_name: &str, mut c: Connection<Db>) -> Result<Accepted<Json<PacketStatsDTO>>, BadRequest<String>> {
    if protocol_name != "odoh" {
        return Err(BadRequest(format!("Protocol {} not found", protocol_name)));
    }
    let protocol: Protocol = protocols::table
        .select(protocols::all_columns)
        .filter(protocols::name.eq(protocol_name))
        .first(&mut c)
        .await
        .map_err(|e| BadRequest(format!("Error fetching protocol: {}", e)))?;

    let packet_dim_avg = protocol.sum_of_packets_size / protocol.packets_n;
    let packet_dim_std_dev = ((protocol.sum_of_squares_of_packets_size / protocol.packets_n) as f64).sqrt() as i32;

    let connection_dim_avg = protocol.sum_of_packets_per_connection / protocol.connection_n;
    let connection_dim_std_dev = ((protocol.sum_of_squares_of_packets_per_connection / protocol.connection_n) as f64).sqrt() as i32;

    //TODO: Aggiungo anche le statistiche nel batch? (quanto peggiore è la performance?)
    Ok(Accepted(Json(PacketStatsDTO::new(
        StatsDTO::new(packet_dim_avg as usize, packet_dim_std_dev as usize),
        StatsDTO::new(connection_dim_avg as usize, connection_dim_std_dev as usize),
    ))))
}

/*
#[post("/<protocol_name>/client", format = "json", data = "<client>")]
async fn register_client(
    protocol_name: &str,
    client: ClientDTO,
    //clients_map: &State<Mutex<ClientsMap>>,
) -> Result<Accepted<Json<PacketStatsDTO>>, BadRequest<String>> {

    let mut clients_map = clients_map.lock().expect("Failed to lock mutex");
    ClientService::register_client(&mut clients_map, client)
        .map_err(|e| BadRequest(format!("Error registering client: {}", e)))?;
    Ok(Accepted(Json(PacketStatsDTO::new(
        StatsDTO::new(100, 10),
        StatsDTO::new(20, 5),
    ))))
}*/

/*
#[delete("/client", format = "json", data = "<flow>")]
async fn unregister_client(
    flow: FlowDTO,
    //clients_map: &State<Mutex<ClientsMap>>,
) -> Result<Created<()>, BadRequest<String>> {
    //let mut clients_map = clients_map.lock().expect("Failed to lock mutex");
    //ClientService::unregister_client(&mut clients_map, flow)
    //    .map_err(|e| BadRequest(format!("Error unregistering client: {}", e)))?;
    Ok(Created::new(""))
}
*/

#[post(
    "/<protocol_name>/packet/size",
    format = "json",
    data = "<packet_size>"
)]
async fn register_packet_size(
    protocol_name: &str,
    packet_size: PacketSizeDTO,
    packet_size_batch: &State<Mutex<PacketSizeBatch>>,
    mut c: Connection<Db>,
) -> Result<Created<()>, BadRequest<String>> {
    let mut packet_size_batch = packet_size_batch.lock().expect("Failed to lock mutex");
    let entry = packet_size_batch.protocols.entry(protocol_name.to_string());
    let stats = match entry {
        Entry::Occupied(e) => {
            let s = e.into_mut();
            s.add_value(packet_size.size as usize);
            s
        }
        Entry::Vacant(e) => {
            let protocol: Protocol = protocols::table
                .select(protocols::all_columns)
                .filter(protocols::name.eq(protocol_name))
                .first(&mut c)
                .await
                .map_err(|e| BadRequest(format!("Error fetching protocol: {}", e)))?;
            let s = Stats{
                n: protocol.packets_n as usize,
                sum: protocol.sum_of_packets_size as usize,
                sum_of_squares: protocol.sum_of_squares_of_packets_size as f64,
            };
            e.insert(s)
        }
    };
    if stats.n % PACKET_SIZE_STATS_BATCH_SIZE == 0 {
        rocket_db_pools::diesel::update(
            protocols::table
                .filter(protocols::name.eq(protocol_name))
        )
            .set((
                protocols::packets_n.eq(stats.n as i32),
                protocols::sum_of_packets_size.eq(stats.sum as i32),
                protocols::sum_of_squares_of_packets_size.eq(stats.sum_of_squares as i32),
            ))
            .execute(&mut c)
            .await
            .map_err(|e| BadRequest(format!("Error updating protocol: {}", e)))?;

    }
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
    packet_number_batch: &State<Mutex<PacketNumberBatch>>,
    mut c: Connection<Db>,
) -> Result<Created<()>, BadRequest<String>> {
    let mut packet_number_batch = packet_number_batch.lock().expect("Failed to lock mutex");
    let entry = packet_number_batch.protocols.entry(protocol_name.to_string());
    let stats = match entry {
        Entry::Occupied(e) => {
            let s = e.into_mut();
            s.add_value(number_of_packets.number as usize);
            s
        }
        Entry::Vacant(e) => {
            let protocol: Protocol = protocols::table
                .select(protocols::all_columns)
                .filter(protocols::name.eq(protocol_name))
                .first(&mut c)
                .await
                .map_err(|e| BadRequest(format!("Error fetching protocol: {}", e)))?;
            let s = Stats{
                n: protocol.connection_n as usize,
                sum: protocol.sum_of_packets_per_connection as usize,
                sum_of_squares: protocol.sum_of_squares_of_packets_per_connection as f64,
            };
            e.insert(s)
        }
    };



    Ok(Created::new(""))
}

#[launch]
fn rocket() -> _ {
    let clients_map = EbpfProgram::run().unwrap_or_else(|e| {
        panic!("Error running eBPF program: {}", e);
    });
    rocket::build()
        //.manage(Mutex::new(clients_map))
        .manage(Mutex::new(PacketSizeBatch { protocols: HashMap::new() }))
        .manage(Mutex::new(PacketNumberBatch { protocols: HashMap::new() }))
        .attach(Db::init())
        .mount(
        "/",
        routes![
            stats,
            //register_client,
            register_packet_size,
            register_packet_number,
            //unregister_client
        ],
    )
}

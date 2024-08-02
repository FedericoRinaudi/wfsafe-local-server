use rocket::serde::Serialize;
use crate::dtos::stats::StatsDTO;

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
pub struct PacketStatsDTO {
    size: StatsDTO,
    number: StatsDTO,
}

impl PacketStatsDTO {
    pub fn new(size: StatsDTO, number: StatsDTO) -> Self {
        Self {
            size,
            number,
        }
    }
}
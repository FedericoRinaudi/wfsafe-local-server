use rocket::serde::Serialize;

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
pub struct StatsDTO {
    avg: usize,
    var: usize,
}

impl StatsDTO {
    pub fn new(avg: usize, var: usize) -> Self {
        Self { avg, var }
    }
}

pub mod schema;

use rocket::response::{Debug};
use rocket::serde::{Deserialize, Serialize};
use rocket_db_pools::{Database, diesel};
use rocket_db_pools::diesel::PgPool;

#[macro_use] extern crate rocket;
type Result<T, E = Debug<diesel::result::Error>> = std::result::Result<T, E>;


#[derive(Database)]
#[database("main_db")]
struct Db(PgPool);

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "rocket::serde")]
pub struct ApiError {
    pub details: String,
}
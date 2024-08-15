use rocket_db_pools::{Database, Connection};
use rocket_db_pools::diesel::{QueryResult, PgPool, prelude::*};

#[derive(Database)]
#[database("wfsafe-stats")]
pub struct StatsDb(PgPool);


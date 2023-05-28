use exun::{RawUnexpected, ResultErrorExt};
use sqlx::MySqlPool;

mod client;
mod user;

pub use client::*;
pub use user::*;

/// Intialize the connection pool
pub async fn initialize(db_url: &str) -> Result<MySqlPool, RawUnexpected> {
	MySqlPool::connect(db_url).await.unexpect()
}

use exun::*;
use sqlx::MySqlPool;

pub async fn initialize(db: &str, user: &str, password: &str) -> Result<MySqlPool, RawUnexpected> {
	let url = format!("mysql://{user}:{password}@localhost/{db}");
	MySqlPool::connect(&url).await.unexpect()
}

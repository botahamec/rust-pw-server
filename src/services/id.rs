use exun::RawUnexpected;
use sqlx::{Executor, MySql};
use uuid::Uuid;

use super::db;

/// Create a unique user id, handling duplicate ID's
pub async fn new_user_id<'c>(
	conn: impl Executor<'c, Database = MySql> + Clone,
) -> Result<Uuid, RawUnexpected> {
	let uuid = loop {
		let uuid = Uuid::new_v4();
		if !db::user_id_exists(conn.clone(), uuid).await? {
			break uuid;
		}
	};

	Ok(uuid)
}

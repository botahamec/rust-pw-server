use std::future::Future;

use exun::RawUnexpected;
use sqlx::{Executor, MySql};
use uuid::Uuid;

/// Create a unique id, handling duplicate ID's.
///
/// The given `unique_check` parameter returns `true` if the ID is used and
/// `false` otherwise.
pub async fn new_id<
	'c,
	E: Executor<'c, Database = MySql> + Clone,
	F: Future<Output = Result<bool, RawUnexpected>>,
>(
	conn: E,
	unique_check: impl Fn(E, Uuid) -> F,
) -> Result<Uuid, RawUnexpected> {
	let uuid = loop {
		let uuid = Uuid::new_v4();
		if !unique_check(conn.clone(), uuid).await? {
			break uuid;
		}
	};

	Ok(uuid)
}

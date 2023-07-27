use std::net::IpAddr;

use chrono::{Duration, Utc};
use exun::RawUnexpected;
use sqlx::{Executor, MySql};

use super::db;

pub const MAX_ATTEMPTS_PER_HOUR: usize = 10;

pub async fn brute_force_detected<'c>(
	executor: impl Executor<'c, Database = MySql>,
	username: &str,
	ip: IpAddr,
) -> Result<bool, RawUnexpected> {
	let since = Utc::now() - Duration::hours(1);
	let attempts = db::failed_login_attempts_since(executor, username, ip, since).await?;
	Ok(attempts > MAX_ATTEMPTS_PER_HOUR)
}

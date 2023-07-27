use std::net::IpAddr;

use chrono::{DateTime, Utc};
use exun::RawUnexpected;
use sqlx::{mysql::MySqlQueryResult, query, query_scalar, Executor, MySql};

pub async fn add_failed_login_attempt<'c>(
	executor: impl Executor<'c, Database = MySql>,
	username: &str,
	ip: IpAddr,
) -> Result<MySqlQueryResult, sqlx::Error> {
	query!(
		"INSERT INTO login_attempts (username, ip_address, time) VALUES (?, ?, ?)",
		username,
		ip.to_string(),
		Utc::now(),
	)
	.execute(executor)
	.await
}

pub async fn failed_login_attempts_since<'c>(
	executor: impl Executor<'c, Database = MySql>,
	username: &str,
	ip: IpAddr,
	time: DateTime<Utc>,
) -> Result<usize, RawUnexpected> {
	let count = query_scalar!(
		r"SELECT COUNT(*) FROM login_attempts WHERE
		  username = ?
		  AND ip_address = ?
		  AND time > ?",
		username,
		ip.to_string(),
		time,
	)
	.fetch_one(executor)
	.await?;

	Ok(count as usize)
}

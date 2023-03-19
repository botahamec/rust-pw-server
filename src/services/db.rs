use exun::*;
use sqlx::{query, query_scalar, Executor, MySql, MySqlPool};
use uuid::Uuid;

use crate::models::User;

/// Intialize the connection pool
pub async fn initialize(db: &str, user: &str, password: &str) -> Result<MySqlPool, RawUnexpected> {
	let url = format!("mysql://{user}:{password}@localhost/{db}");
	MySqlPool::connect(&url).await.unexpect()
}

pub async fn user_id_exists<'c>(
	conn: impl Executor<'c, Database = MySql>,
	id: Uuid,
) -> Result<bool, RawUnexpected> {
	let exists = query_scalar!(
		r#"SELECT EXISTS(SELECT user_id FROM users WHERE user_id = ?) as "e: bool""#,
		id
	)
	.fetch_one(conn)
	.await?;

	Ok(exists)
}

pub async fn username_is_used<'c>(
	conn: impl Executor<'c, Database = MySql>,
	username: &str,
) -> Result<bool, RawUnexpected> {
	let exists = query_scalar!(
		r#"SELECT EXISTS(SELECT user_id FROM users WHERE username = ?) as "e: bool""#,
		username
	)
	.fetch_one(conn)
	.await?;

	Ok(exists)
}

pub async fn new_user<'c>(
	conn: impl Executor<'c, Database = MySql>,
	user: User,
) -> Result<sqlx::mysql::MySqlQueryResult, sqlx::Error> {
	query!(
		r"INSERT INTO users (user_id, username, password_hash, password_salt, password_version)
					 VALUES (?,       ?,        ?,             ?,             ?)",
		user.user_id,
		user.username(),
		user.password_hash(),
		user.password_salt(),
		user.password_version()
	)
	.execute(conn)
	.await
}

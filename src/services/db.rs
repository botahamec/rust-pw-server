use exun::*;
use sqlx::{mysql::MySqlQueryResult, query, query_as, query_scalar, Executor, MySql, MySqlPool};
use uuid::Uuid;

use crate::models::User;

use super::crypto::PasswordHash;

struct UserRow {
	user_id: Vec<u8>,
	username: String,
	password_hash: Vec<u8>,
	password_salt: Vec<u8>,
	password_version: u32,
}

impl TryFrom<UserRow> for User {
	type Error = RawUnexpected;

	fn try_from(row: UserRow) -> Result<Self, Self::Error> {
		let password = PasswordHash::from_fields(
			&row.password_hash,
			&row.password_salt,
			row.password_version as u8,
		);
		let user = User {
			user_id: Uuid::from_slice(&row.user_id)?,
			username: row.username.into_boxed_str(),
			password,
		};
		Ok(user)
	}
}

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

pub async fn get_user<'c>(
	conn: impl Executor<'c, Database = MySql>,
	user_id: Uuid,
) -> Result<Option<User>, RawUnexpected> {
	let record = query_as!(
		UserRow,
		r"SELECT user_id, username, password_hash, password_salt, password_version
		  FROM users WHERE user_id = ?",
		user_id
	)
	.fetch_optional(conn)
	.await?;

	let Some(record) = record else { return Ok(None) };

	Ok(Some(record.try_into()?))
}

pub async fn get_username<'c>(
	conn: impl Executor<'c, Database = MySql>,
	user_id: Uuid,
) -> Result<Option<Box<str>>, RawUnexpected> {
	let username = query_scalar!(r"SELECT username FROM users where user_id = ?", user_id)
		.fetch_optional(conn)
		.await?
		.map(String::into_boxed_str);

	Ok(username)
}

pub async fn new_user<'c>(
	conn: impl Executor<'c, Database = MySql>,
	user: &User,
) -> Result<MySqlQueryResult, sqlx::Error> {
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

pub async fn update_user<'c>(
	conn: impl Executor<'c, Database = MySql>,
	user: &User,
) -> Result<MySqlQueryResult, sqlx::Error> {
	query!(
		r"UPDATE users SET
		  username = ?,
		  password_hash = ?,
		  password_salt = ?,
		  password_version = ?
		  WHERE user_id = ?",
		user.username(),
		user.password_hash(),
		user.password_salt(),
		user.password_version(),
		user.user_id
	)
	.execute(conn)
	.await
}

pub async fn update_username<'c>(
	conn: impl Executor<'c, Database = MySql>,
	user_id: Uuid,
	username: &str,
) -> Result<MySqlQueryResult, sqlx::Error> {
	query!(
		r"UPDATE users SET username = ? WHERE user_id = ?",
		username,
		user_id
	)
	.execute(conn)
	.await
}

pub async fn update_password<'c>(
	conn: impl Executor<'c, Database = MySql>,
	user_id: Uuid,
	password: &PasswordHash,
) -> Result<MySqlQueryResult, sqlx::Error> {
	query!(
		r"UPDATE users SET
		password_hash = ?,
		password_salt = ?,
		password_version = ?
		WHERE user_id = ?",
		password.hash(),
		password.salt(),
		password.version(),
		user_id
	)
	.execute(conn)
	.await
}

use exun::RawUnexpected;
use sqlx::{mysql::MySqlQueryResult, query, query_as, query_scalar, Executor, MySql};
use uuid::Uuid;

use crate::{models::user::User, services::crypto::PasswordHash};

struct UserRow {
	id: Uuid,
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
			id: row.id,
			username: row.username.into_boxed_str(),
			password,
		};
		Ok(user)
	}
}

/// Check if a user with a given user ID exists
pub async fn user_id_exists<'c>(
	conn: impl Executor<'c, Database = MySql>,
	id: Uuid,
) -> Result<bool, RawUnexpected> {
	let exists = query_scalar!(
		r#"SELECT EXISTS(SELECT id FROM users WHERE id = ?) as `e: bool`"#,
		id
	)
	.fetch_one(conn)
	.await?;

	Ok(exists)
}

/// Check if a given username is taken
pub async fn username_is_used<'c>(
	conn: impl Executor<'c, Database = MySql>,
	username: &str,
) -> Result<bool, RawUnexpected> {
	let exists = query_scalar!(
		r#"SELECT EXISTS(SELECT id FROM users WHERE username = ?) as "e: bool""#,
		username
	)
	.fetch_one(conn)
	.await?;

	Ok(exists)
}

/// Get a user from their ID
pub async fn get_user<'c>(
	conn: impl Executor<'c, Database = MySql>,
	user_id: Uuid,
) -> Result<Option<User>, RawUnexpected> {
	let record = query_as!(
		UserRow,
		r"SELECT id as `id: Uuid`, username, password_hash, password_salt, password_version
		  FROM users WHERE id = ?",
		user_id
	)
	.fetch_optional(conn)
	.await?;

	let Some(record) = record else { return Ok(None) };

	Ok(Some(record.try_into()?))
}

/// Get a user from their username
pub async fn get_user_by_username<'c>(
	conn: impl Executor<'c, Database = MySql>,
	username: &str,
) -> Result<Option<User>, RawUnexpected> {
	let record = query_as!(
		UserRow,
		r"SELECT id as `id: Uuid`, username, password_hash, password_salt, password_version
		  FROM users WHERE username = ?",
		username
	)
	.fetch_optional(conn)
	.await?;

	let Some(record) = record else { return Ok(None) };

	Ok(Some(record.try_into()?))
}

/// Search the list of users for a given username
pub async fn search_users<'c>(
	conn: impl Executor<'c, Database = MySql>,
	username: &str,
) -> Result<Box<[User]>, RawUnexpected> {
	let records = query_as!(
		UserRow,
		r"SELECT id as `id: Uuid`, username, password_hash, password_salt, password_version
		  FROM users
		  WHERE LOCATE(?, username) != 0",
		username,
	)
	.fetch_all(conn)
	.await?;

	Ok(records
		.into_iter()
		.map(|u| u.try_into())
		.collect::<Result<Box<[User]>, RawUnexpected>>()?)
}

/// Search the list of users, only returning a certain range of results
pub async fn search_users_limit<'c>(
	conn: impl Executor<'c, Database = MySql>,
	username: &str,
	offset: u32,
	limit: u32,
) -> Result<Box<[User]>, RawUnexpected> {
	let records = query_as!(
		UserRow,
		r"SELECT id as `id: Uuid`, username, password_hash, password_salt, password_version
		  FROM users
		  WHERE LOCATE(?, username) != 0
		  LIMIT ?
		  OFFSET ?",
		username,
		offset,
		limit
	)
	.fetch_all(conn)
	.await?;

	Ok(records
		.into_iter()
		.map(|u| u.try_into())
		.collect::<Result<Box<[User]>, RawUnexpected>>()?)
}

/// Get the username of a user with a certain ID
pub async fn get_username<'c>(
	conn: impl Executor<'c, Database = MySql>,
	user_id: Uuid,
) -> Result<Option<Box<str>>, RawUnexpected> {
	let username = query_scalar!(r"SELECT username FROM users where id = ?", user_id)
		.fetch_optional(conn)
		.await?
		.map(String::into_boxed_str);

	Ok(username)
}

/// Create a new user
pub async fn create_user<'c>(
	conn: impl Executor<'c, Database = MySql>,
	user: &User,
) -> Result<MySqlQueryResult, sqlx::Error> {
	query!(
		r"INSERT INTO users (id, username, password_hash, password_salt, password_version)
					 VALUES ( ?,        ?,             ?,             ?,                ?)",
		user.id,
		user.username(),
		user.password_hash(),
		user.password_salt(),
		user.password_version()
	)
	.execute(conn)
	.await
}

/// Update a user
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
		  WHERE id = ?",
		user.username(),
		user.password_hash(),
		user.password_salt(),
		user.password_version(),
		user.id
	)
	.execute(conn)
	.await
}

/// Update the username of a user with the given ID
pub async fn update_username<'c>(
	conn: impl Executor<'c, Database = MySql>,
	user_id: Uuid,
	username: &str,
) -> Result<MySqlQueryResult, sqlx::Error> {
	query!(
		r"UPDATE users SET username = ? WHERE id = ?",
		username,
		user_id
	)
	.execute(conn)
	.await
}

/// Update the password of a user with the given ID
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
		WHERE id = ?",
		password.hash(),
		password.salt(),
		password.version(),
		user_id
	)
	.execute(conn)
	.await
}

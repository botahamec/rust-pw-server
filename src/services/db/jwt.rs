use chrono::{DateTime, Utc};
use exun::{RawUnexpected, ResultErrorExt};
use sqlx::{query, query_scalar, Executor, MySql};
use uuid::Uuid;

use crate::services::jwt::RevokedRefreshTokenReason;

pub async fn auth_code_exists<'c>(
	executor: impl Executor<'c, Database = MySql>,
	jti: Uuid,
) -> Result<bool, RawUnexpected> {
	query_scalar!(
		"SELECT EXISTS(SELECT jti FROM auth_codes WHERE jti = ?) as `e: bool`",
		jti
	)
	.fetch_one(executor)
	.await
	.unexpect()
}

pub async fn access_token_exists<'c>(
	executor: impl Executor<'c, Database = MySql>,
	jti: Uuid,
) -> Result<bool, RawUnexpected> {
	query_scalar!(
		"SELECT EXISTS(SELECT jti FROM access_tokens WHERE jti = ?) as `e: bool`",
		jti
	)
	.fetch_one(executor)
	.await
	.unexpect()
}

pub async fn refresh_token_exists<'c>(
	executor: impl Executor<'c, Database = MySql>,
	jti: Uuid,
) -> Result<bool, RawUnexpected> {
	query_scalar!(
		"SELECT EXISTS(SELECT jti FROM refresh_tokens WHERE jti = ?) as `e: bool`",
		jti
	)
	.fetch_one(executor)
	.await
	.unexpect()
}

pub async fn refresh_token_revoked<'c>(
	executor: impl Executor<'c, Database = MySql>,
	jti: Uuid,
) -> Result<bool, RawUnexpected> {
	let result = query_scalar!(
		r"SELECT EXISTS(
			SELECT revoked_reason FROM refresh_tokens WHERE jti = ? and revoked_reason IS NOT NULL
		) as `e: bool`",
		jti
	)
	.fetch_one(executor)
	.await?
	.unwrap_or(true);

	Ok(result)
}

pub async fn create_auth_code<'c>(
	executor: impl Executor<'c, Database = MySql>,
	jti: Uuid,
	exp: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
	query!(
		r"INSERT INTO auth_codes (jti, exp)
	                VALUES       (  ?,   ?)",
		jti,
		exp
	)
	.execute(executor)
	.await?;

	Ok(())
}

pub async fn create_access_token<'c>(
	executor: impl Executor<'c, Database = MySql>,
	jti: Uuid,
	auth_code: Uuid,
	exp: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
	query!(
		r"INSERT INTO access_tokens (jti, auth_code, exp)
	                         VALUES (  ?,         ?,   ?)",
		jti,
		auth_code,
		exp
	)
	.execute(executor)
	.await?;

	Ok(())
}

pub async fn create_refresh_token<'c>(
	executor: impl Executor<'c, Database = MySql>,
	jti: Uuid,
	auth_code: Uuid,
	exp: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
	query!(
		r"INSERT INTO access_tokens (jti, auth_code, exp)
	                         VALUES (  ?,         ?,   ?)",
		jti,
		auth_code,
		exp
	)
	.execute(executor)
	.await?;

	Ok(())
}

pub async fn delete_auth_code<'c>(
	executor: impl Executor<'c, Database = MySql>,
	auth_code: Uuid,
) -> Result<bool, RawUnexpected> {
	let result = query!("DELETE FROM auth_codes WHERE jti = ?", auth_code)
		.execute(executor)
		.await?;

	Ok(result.rows_affected() != 0)
}

pub async fn delete_expired_auth_codes<'c>(
	executor: impl Executor<'c, Database = MySql>,
) -> Result<(), RawUnexpected> {
	query!("DELETE FROM auth_codes WHERE exp < ?", Utc::now())
		.execute(executor)
		.await?;

	Ok(())
}

pub async fn delete_access_tokens_with_auth_code<'c>(
	executor: impl Executor<'c, Database = MySql>,
	auth_code: Uuid,
) -> Result<bool, RawUnexpected> {
	let result = query!("DELETE FROM access_tokens WHERE auth_code = ?", auth_code)
		.execute(executor)
		.await?;

	Ok(result.rows_affected() != 0)
}

pub async fn delete_expired_access_tokens<'c>(
	executor: impl Executor<'c, Database = MySql>,
) -> Result<(), RawUnexpected> {
	query!("DELETE FROM access_tokens WHERE exp < ?", Utc::now())
		.execute(executor)
		.await?;

	Ok(())
}

pub async fn revoke_refresh_token<'c>(
	executor: impl Executor<'c, Database = MySql>,
	jti: Uuid,
) -> Result<bool, RawUnexpected> {
	let result = query!(
		"UPDATE refresh_tokens SET revoked_reason = ? WHERE jti = ?",
		RevokedRefreshTokenReason::NewRefreshToken,
		jti
	)
	.execute(executor)
	.await?;

	Ok(result.rows_affected() != 0)
}

pub async fn revoke_refresh_tokens_with_auth_code<'c>(
	executor: impl Executor<'c, Database = MySql>,
	auth_code: Uuid,
) -> Result<bool, RawUnexpected> {
	let result = query!(
		"UPDATE refresh_tokens SET revoked_reason = ? WHERE auth_code = ?",
		RevokedRefreshTokenReason::ReusedAuthorizationCode,
		auth_code
	)
	.execute(executor)
	.await?;

	Ok(result.rows_affected() != 0)
}

pub async fn delete_expired_refresh_tokens<'c>(
	executor: impl Executor<'c, Database = MySql>,
) -> Result<(), RawUnexpected> {
	query!("DELETE FROM refresh_tokens WHERE exp < ?", Utc::now())
		.execute(executor)
		.await?;

	Ok(())
}

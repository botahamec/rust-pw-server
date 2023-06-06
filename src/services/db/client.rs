use std::str::FromStr;

use exun::{RawUnexpected, ResultErrorExt};
use sqlx::{
	mysql::MySqlQueryResult, query, query_as, query_scalar, Executor, FromRow, MySql, Transaction,
};
use url::Url;
use uuid::Uuid;

use crate::{
	models::client::{Client, ClientType},
	services::crypto::PasswordHash,
};

#[derive(Debug, Clone, FromRow)]
pub struct ClientRow {
	pub id: Uuid,
	pub alias: String,
	pub client_type: ClientType,
	pub allowed_scopes: String,
	pub default_scopes: Option<String>,
}

pub async fn client_id_exists<'c>(
	executor: impl Executor<'c, Database = MySql>,
	id: Uuid,
) -> Result<bool, RawUnexpected> {
	query_scalar!(
		r"SELECT EXISTS(SELECT id FROM clients WHERE id = ?) as `e: bool`",
		id
	)
	.fetch_one(executor)
	.await
	.unexpect()
}

pub async fn client_alias_exists<'c>(
	executor: impl Executor<'c, Database = MySql>,
	alias: &str,
) -> Result<bool, RawUnexpected> {
	query_scalar!(
		"SELECT EXISTS(SELECT alias FROM clients WHERE alias = ?) as `e: bool`",
		alias
	)
	.fetch_one(executor)
	.await
	.unexpect()
}

pub async fn get_client_response<'c>(
	executor: impl Executor<'c, Database = MySql>,
	id: Uuid,
) -> Result<Option<ClientRow>, RawUnexpected> {
	let record = query_as!(
		ClientRow,
		r"SELECT id as `id: Uuid`,
		         alias,
				 type as `client_type: ClientType`,
				 allowed_scopes,
				 default_scopes
		  FROM clients WHERE id = ?",
		id
	)
	.fetch_optional(executor)
	.await?;

	Ok(record)
}

pub async fn get_client_alias<'c>(
	executor: impl Executor<'c, Database = MySql>,
	id: Uuid,
) -> Result<Option<Box<str>>, RawUnexpected> {
	let alias = query_scalar!("SELECT alias FROM clients WHERE id = ?", id)
		.fetch_optional(executor)
		.await
		.unexpect()?;

	Ok(alias.map(String::into_boxed_str))
}

pub async fn get_client_type<'c>(
	executor: impl Executor<'c, Database = MySql>,
	id: Uuid,
) -> Result<Option<ClientType>, RawUnexpected> {
	let ty = query_scalar!(
		"SELECT type as `type: ClientType` FROM clients WHERE id = ?",
		id
	)
	.fetch_optional(executor)
	.await
	.unexpect()?;

	Ok(ty)
}

pub async fn get_client_redirect_uris<'c>(
	executor: impl Executor<'c, Database = MySql>,
	id: Uuid,
) -> Result<Box<[Url]>, RawUnexpected> {
	let uris = query_scalar!(
		"SELECT redirect_uri FROM client_redirect_uris WHERE client_id = ?",
		id
	)
	.fetch_all(executor)
	.await
	.unexpect()?;

	uris.into_iter()
		.map(|s| Url::from_str(&s).unexpect())
		.collect()
}

pub async fn client_has_redirect_uri<'c>(
	executor: impl Executor<'c, Database = MySql>,
	id: Uuid,
	url: Url,
) -> Result<bool, RawUnexpected> {
	query_scalar!(
		r"SELECT EXISTS(
			  SELECT redirect_uri
			  FROM client_redirect_uris
			  WHERE client_id = ? AND redirect_uri = ?
		  ) as `e: bool`",
		id,
		url.to_string()
	)
	.fetch_one(executor)
	.await
	.unexpect()
}

async fn delete_client_redirect_uris<'c>(
	executor: impl Executor<'c, Database = MySql>,
	id: Uuid,
) -> Result<(), sqlx::Error> {
	query!("DELETE FROM client_redirect_uris WHERE client_id = ?", id)
		.execute(executor)
		.await?;
	Ok(())
}

async fn create_client_redirect_uris<'c>(
	mut transaction: Transaction<'c, MySql>,
	client_id: Uuid,
	uris: &[Url],
) -> Result<(), sqlx::Error> {
	for uri in uris {
		query!(
			r"INSERT INTO client_redirect_uris (client_id, redirect_uri)
									    VALUES (        ?,            ?)",
			client_id,
			uri.to_string()
		)
		.execute(&mut transaction)
		.await?;
	}

	transaction.commit().await?;

	Ok(())
}

pub async fn create_client<'c>(
	mut transaction: Transaction<'c, MySql>,
	client: &Client,
) -> Result<(), sqlx::Error> {
	query!(
		r"INSERT INTO clients (id, alias, type, secret_hash, secret_salt, secret_version, allowed_scopes, default_scopes)
					   VALUES ( ?,     ?,    ?,           ?,           ?,              ?,              ?,              ?)",
		client.id(),
		client.alias(),
		client.client_type(),
		client.secret_hash(),
		client.secret_salt(),
		client.secret_version(),
		client.allowed_scopes(),
		client.default_scopes()
	)
	.execute(&mut transaction)
	.await?;

	create_client_redirect_uris(transaction, client.id(), client.redirect_uris()).await?;

	Ok(())
}

pub async fn update_client<'c>(
	mut transaction: Transaction<'c, MySql>,
	client: &Client,
) -> Result<(), sqlx::Error> {
	query!(
		r"UPDATE clients SET
		alias = ?,
		type = ?,
		secret_hash = ?,
		secret_salt = ?,
		secret_version = ?,
		allowed_scopes = ?,
		default_scopes = ?
		WHERE id = ?",
		client.client_type(),
		client.alias(),
		client.secret_hash(),
		client.secret_salt(),
		client.secret_version(),
		client.allowed_scopes(),
		client.default_scopes(),
		client.id()
	)
	.execute(&mut transaction)
	.await?;

	update_client_redirect_uris(transaction, client.id(), client.redirect_uris()).await?;

	Ok(())
}

pub async fn update_client_alias<'c>(
	executor: impl Executor<'c, Database = MySql>,
	id: Uuid,
	alias: &str,
) -> Result<MySqlQueryResult, sqlx::Error> {
	query!("UPDATE clients SET alias = ? WHERE id = ?", alias, id)
		.execute(executor)
		.await
}

pub async fn update_client_type<'c>(
	executor: impl Executor<'c, Database = MySql>,
	id: Uuid,
	ty: ClientType,
) -> Result<MySqlQueryResult, sqlx::Error> {
	query!("UPDATE clients SET type = ? WHERE id = ?", ty, id)
		.execute(executor)
		.await
}

pub async fn update_client_redirect_uris<'c>(
	mut transaction: Transaction<'c, MySql>,
	id: Uuid,
	uris: &[Url],
) -> Result<(), sqlx::Error> {
	delete_client_redirect_uris(&mut transaction, id).await?;
	create_client_redirect_uris(transaction, id, uris).await?;
	Ok(())
}

pub async fn update_client_secret<'c>(
	executor: impl Executor<'c, Database = MySql>,
	id: Uuid,
	secret: Option<PasswordHash>,
) -> Result<MySqlQueryResult, sqlx::Error> {
	if let Some(secret) = secret {
		query!(
			"UPDATE clients SET secret_hash = ?, secret_salt = ?, secret_version = ? WHERE id = ?",
			secret.hash(),
			secret.salt(),
			secret.version(),
			id
		)
		.execute(executor)
		.await
	} else {
		query!(
			r"UPDATE clients
			  SET secret_hash = NULL, secret_salt = NULL, secret_version = NULL
			  WHERE id = ?",
			id
		)
		.execute(executor)
		.await
	}
}

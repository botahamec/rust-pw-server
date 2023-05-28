use actix_web::http::{header, StatusCode};
use actix_web::{get, post, put, web, HttpResponse, ResponseError, Scope};
use raise::yeet;
use serde::Deserialize;
use sqlx::MySqlPool;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::models::client::{Client, ClientType, NoSecretError};
use crate::services::crypto::PasswordHash;
use crate::services::{db, id};

#[derive(Debug, Clone, Copy, Error)]
#[error("No client with the given client ID was found")]
struct ClientNotFound {
	id: Uuid,
}

impl ResponseError for ClientNotFound {
	fn status_code(&self) -> StatusCode {
		StatusCode::NOT_FOUND
	}
}

impl ClientNotFound {
	fn new(id: Uuid) -> Self {
		Self { id }
	}
}

#[get("/{client_id}")]
async fn get_client(
	client_id: web::Path<Uuid>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, ClientNotFound> {
	let db = db.as_ref();
	let id = *client_id;

	let Some(client) = db::get_client_response(db, id).await.unwrap() else {
		yeet!(ClientNotFound::new(id))
	};

	let redirect_uris_link = format!("</clients/{client_id}/redirect-uris>; rel=\"redirect-uris\"");
	let response = HttpResponse::Ok()
		.append_header((header::LINK, redirect_uris_link))
		.json(client);
	Ok(response)
}

#[get("/{client_id}/alias")]
async fn get_client_alias(
	client_id: web::Path<Uuid>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, ClientNotFound> {
	let db = db.as_ref();
	let id = *client_id;

	let Some(alias) = db::get_client_alias(db, id).await.unwrap() else {
		yeet!(ClientNotFound::new(id))
	};

	Ok(HttpResponse::Ok().json(alias))
}

#[get("/{client_id}/type")]
async fn get_client_type(
	client_id: web::Path<Uuid>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, ClientNotFound> {
	let db = db.as_ref();
	let id = *client_id;

	let Some(client_type) = db::get_client_type(db, id).await.unwrap() else {
		yeet!(ClientNotFound::new(id))
	};

	Ok(HttpResponse::Ok().json(client_type))
}

#[get("/{client_id}/redirect-uris")]
async fn get_client_redirect_uris(
	client_id: web::Path<Uuid>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, ClientNotFound> {
	let db = db.as_ref();
	let id = *client_id;

	if !db::client_id_exists(db, id).await.unwrap() {
		yeet!(ClientNotFound::new(id))
	};

	let redirect_uris = db::get_client_redirect_uris(db, id).await.unwrap();

	Ok(HttpResponse::Ok().json(redirect_uris))
}

#[derive(Debug, Clone, Deserialize)]
struct ClientRequest {
	alias: Box<str>,
	ty: ClientType,
	redirect_uris: Box<[Url]>,
	secret: Option<Box<str>>,
}

#[derive(Debug, Clone, Error)]
#[error("The given client alias is already taken")]
struct AliasTakenError {
	alias: Box<str>,
}

impl ResponseError for AliasTakenError {
	fn status_code(&self) -> StatusCode {
		StatusCode::CONFLICT
	}
}

impl AliasTakenError {
	fn new(alias: &str) -> Self {
		Self {
			alias: Box::from(alias),
		}
	}
}

#[post("")]
async fn create_client(
	body: web::Json<ClientRequest>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, UpdateClientError> {
	let db = db.get_ref();
	let alias = &body.alias;

	if db::client_alias_exists(db, &alias).await.unwrap() {
		yeet!(AliasTakenError::new(&alias).into());
	}

	let id = id::new_id(db, db::client_id_exists).await.unwrap();
	let client = Client::new(
		id,
		&alias,
		body.ty,
		body.secret.as_deref(),
		&body.redirect_uris,
	)
	.map_err(|e| e.unwrap())?;

	let transaction = db.begin().await.unwrap();
	db::create_client(transaction, &client).await.unwrap();

	let response = HttpResponse::Created()
		.insert_header((header::LOCATION, format!("clients/{id}")))
		.finish();
	Ok(response)
}

#[derive(Debug, Clone, Error)]
enum UpdateClientError {
	#[error(transparent)]
	NotFound(#[from] ClientNotFound),
	#[error(transparent)]
	NoSecret(#[from] NoSecretError),
	#[error(transparent)]
	AliasTaken(#[from] AliasTakenError),
}

impl ResponseError for UpdateClientError {
	fn status_code(&self) -> StatusCode {
		match self {
			Self::NotFound(e) => e.status_code(),
			Self::NoSecret(e) => e.status_code(),
			Self::AliasTaken(e) => e.status_code(),
		}
	}
}

#[put("/{id}")]
async fn update_client(
	id: web::Path<Uuid>,
	body: web::Json<ClientRequest>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, UpdateClientError> {
	let db = db.get_ref();
	let id = *id;
	let alias = &body.alias;

	let Some(old_alias) = db::get_client_alias(db, id).await.unwrap() else {
		yeet!(ClientNotFound::new(id).into())
	};
	if old_alias != alias.clone() && db::client_alias_exists(db, &alias).await.unwrap() {
		yeet!(AliasTakenError::new(&alias).into());
	}

	let client = Client::new(
		id,
		&alias,
		body.ty,
		body.secret.as_deref(),
		&body.redirect_uris,
	)
	.map_err(|e| e.unwrap())?;

	let transaction = db.begin().await.unwrap();
	db::update_client(transaction, &client).await.unwrap();

	let response = HttpResponse::NoContent().finish();
	Ok(response)
}

#[put("/{id}/alias")]
async fn update_client_alias(
	id: web::Path<Uuid>,
	body: web::Json<Box<str>>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, UpdateClientError> {
	let db = db.get_ref();
	let id = *id;
	let alias = body.0;

	let Some(old_alias) = db::get_client_alias(db, id).await.unwrap() else {
		yeet!(ClientNotFound::new(id).into())
	};
	if old_alias == alias {
		return Ok(HttpResponse::NoContent().finish());
	}
	if db::client_alias_exists(db, &alias).await.unwrap() {
		yeet!(AliasTakenError::new(&alias).into());
	}

	db::update_client_alias(db, id, &alias).await.unwrap();

	let response = HttpResponse::NoContent().finish();
	Ok(response)
}

#[put("/{id}/type")]
async fn update_client_type(
	id: web::Path<Uuid>,
	body: web::Json<ClientType>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, UpdateClientError> {
	let db = db.get_ref();
	let id = *id;
	let ty = body.0;

	if !db::client_id_exists(db, id).await.unwrap() {
		yeet!(ClientNotFound::new(id).into());
	}

	db::update_client_type(db, id, ty).await.unwrap();

	Ok(HttpResponse::NoContent().finish())
}

#[put("/{id}/redirect-uris")]
async fn update_client_redirect_uris(
	id: web::Path<Uuid>,
	body: web::Json<Box<[Url]>>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, UpdateClientError> {
	let db = db.get_ref();
	let id = *id;

	if !db::client_id_exists(db, id).await.unwrap() {
		yeet!(ClientNotFound::new(id).into());
	}

	let transaction = db.begin().await.unwrap();
	db::update_client_redirect_uris(transaction, id, &body.0)
		.await
		.unwrap();

	Ok(HttpResponse::NoContent().finish())
}

#[put("{id}/secret")]
async fn update_client_secret(
	id: web::Path<Uuid>,
	body: web::Json<Option<Box<str>>>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, UpdateClientError> {
	let db = db.get_ref();
	let id = *id;

	let Some(client_type) = db::get_client_type(db, id).await.unwrap() else {
		yeet!(ClientNotFound::new(id).into())
	};

	if client_type == ClientType::Confidential && body.is_none() {
		yeet!(NoSecretError::new().into())
	}

	let secret = body.0.map(|s| PasswordHash::new(&s).unwrap());
	db::update_client_secret(db, id, secret).await.unwrap();

	Ok(HttpResponse::NoContent().finish())
}

pub fn service() -> Scope {
	web::scope("/clients")
		.service(get_client)
		.service(get_client_alias)
		.service(get_client_type)
		.service(get_client_redirect_uris)
		.service(create_client)
		.service(update_client)
		.service(update_client_alias)
		.service(update_client_type)
		.service(update_client_redirect_uris)
		.service(update_client_secret)
}

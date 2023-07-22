use actix_web::http::{header, StatusCode};
use actix_web::{get, post, put, web, HttpResponse, ResponseError, Scope};
use raise::yeet;
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::models::client::{Client, ClientType, CreateClientError};
use crate::services::crypto::PasswordHash;
use crate::services::db::ClientRow;
use crate::services::{db, id};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientResponse {
	client_id: Uuid,
	alias: Box<str>,
	client_type: ClientType,
	allowed_scopes: Box<[Box<str>]>,
	default_scopes: Option<Box<[Box<str>]>>,
	is_trusted: bool,
}

impl From<ClientRow> for ClientResponse {
	fn from(value: ClientRow) -> Self {
		Self {
			client_id: value.id,
			alias: value.alias.into_boxed_str(),
			client_type: value.client_type,
			allowed_scopes: value
				.allowed_scopes
				.split_whitespace()
				.map(Box::from)
				.collect(),
			default_scopes: value
				.default_scopes
				.map(|s| s.split_whitespace().map(Box::from).collect()),
			is_trusted: value.is_trusted,
		}
	}
}

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
	let response: ClientResponse = client.into();
	let response = HttpResponse::Ok()
		.append_header((header::LINK, redirect_uris_link))
		.json(response);
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

#[get("/{client_id}/client-type")]
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

#[get("/{client_id}/allowed-scopes")]
async fn get_client_allowed_scopes(
	client_id: web::Path<Uuid>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, ClientNotFound> {
	let db = db.as_ref();
	let id = *client_id;

	let Some(allowed_scopes) = db::get_client_allowed_scopes(db, id).await.unwrap() else {
		yeet!(ClientNotFound::new(id))
	};

	let allowed_scopes = allowed_scopes.split_whitespace().collect::<Box<[&str]>>();

	Ok(HttpResponse::Ok().json(allowed_scopes))
}

#[get("/{client_id}/default-scopes")]
async fn get_client_default_scopes(
	client_id: web::Path<Uuid>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, ClientNotFound> {
	let db = db.as_ref();
	let id = *client_id;

	let Some(default_scopes) = db::get_client_default_scopes(db, id).await.unwrap() else {
		yeet!(ClientNotFound::new(id))
	};

	let default_scopes = default_scopes.map(|scopes| {
		scopes
			.split_whitespace()
			.map(Box::from)
			.collect::<Box<[Box<str>]>>()
	});

	Ok(HttpResponse::Ok().json(default_scopes))
}

#[get("/{client_id}/is-trusted")]
async fn get_client_is_trusted(
	client_id: web::Path<Uuid>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, ClientNotFound> {
	let db = db.as_ref();
	let id = *client_id;

	let Some(is_trusted) = db::is_client_trusted(db, id).await.unwrap() else {
		yeet!(ClientNotFound::new(id))
	};

	Ok(HttpResponse::Ok().json(is_trusted))
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientRequest {
	alias: Box<str>,
	client_type: ClientType,
	redirect_uris: Box<[Url]>,
	secret: Option<Box<str>>,
	allowed_scopes: Box<[Box<str>]>,
	default_scopes: Option<Box<[Box<str>]>>,
	trusted: bool,
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
		body.client_type,
		body.secret.as_deref(),
		body.allowed_scopes.clone(),
		body.default_scopes.clone(),
		&body.redirect_uris,
		body.trusted,
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
	ClientError(#[from] CreateClientError),
	#[error(transparent)]
	AliasTaken(#[from] AliasTakenError),
}

impl ResponseError for UpdateClientError {
	fn status_code(&self) -> StatusCode {
		match self {
			Self::NotFound(e) => e.status_code(),
			Self::ClientError(e) => e.status_code(),
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
		body.client_type,
		body.secret.as_deref(),
		body.allowed_scopes.clone(),
		body.default_scopes.clone(),
		&body.redirect_uris,
		body.trusted,
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

#[put("/{id}/client-type")]
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

	if db::is_client_trusted(db, id).await.unwrap().unwrap() {
		yeet!(CreateClientError::TrustedError.into())
	}

	if *body == ClientType::Confidential && db::get_client_secret(db, id).await.unwrap().is_none() {
		yeet!(CreateClientError::NoSecret.into())
	}

	db::update_client_type(db, id, ty).await.unwrap();

	Ok(HttpResponse::NoContent().finish())
}

// TODO validate that a client is valid before sending it to the DB
// TODO add DELETE endpoints where appropriate
// TODO add PATCH endpoints where appropriate
// TODO fix more race conditions

#[put("/{id}/allowed-scopes")]
async fn update_client_allowed_scopes(
	id: web::Path<Uuid>,
	body: web::Json<Box<[Box<str>]>>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, UpdateClientError> {
	let db = db.get_ref();
	let id = *id;
	let allowed_scopes = body.0.join(" ");

	if !db::client_id_exists(db, id).await.unwrap() {
		yeet!(ClientNotFound::new(id).into());
	}

	if let Some(default_scopes) = db::get_client_default_scopes(db, id)
		.await
		.unwrap()
		.unwrap()
	{
		if !crate::scopes::is_subset_of(&default_scopes, &allowed_scopes) {
			yeet!(CreateClientError::ImpermissibleDefaultScopes.into());
		}
	}

	db::update_client_allowed_scopes(db, id, &allowed_scopes)
		.await
		.unwrap();

	Ok(HttpResponse::NoContent().finish())
}

#[put("/{id}/default-scopes")]
async fn update_client_default_scopes(
	id: web::Path<Uuid>,
	body: web::Json<Option<Box<[Box<str>]>>>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, UpdateClientError> {
	let db = db.get_ref();
	let id = *id;
	let default_scopes = body.0.map(|s| s.join(" "));

	if !db::client_id_exists(db, id).await.unwrap() {
		yeet!(ClientNotFound::new(id).into());
	}

	let allowed_scopes = db::get_client_allowed_scopes(db, id)
		.await
		.unwrap()
		.unwrap();

	if let Some(default_scopes) = &default_scopes {
		if !crate::scopes::is_subset_of(default_scopes, &allowed_scopes) {
			yeet!(CreateClientError::ImpermissibleDefaultScopes.into());
		}
	}

	db::update_client_default_scopes(db, id, default_scopes)
		.await
		.unwrap();

	Ok(HttpResponse::NoContent().finish())
}

#[put("/{id}/is-trusted")]
async fn update_client_is_trusted(
	id: web::Path<Uuid>,
	body: web::Json<bool>,
	db: web::Data<MySqlPool>,
) -> Result<HttpResponse, UpdateClientError> {
	let db = db.get_ref();
	let id = *id;
	let is_trusted = *body;

	if !db::client_id_exists(db, id).await.unwrap() {
		yeet!(ClientNotFound::new(id).into());
	}

	db::update_client_trusted(db, id, is_trusted).await.unwrap();

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

	for uri in body.0.iter() {
		if uri.scheme() != "https" {
			yeet!(CreateClientError::NonHttpsUri.into());
		}

		if uri.fragment().is_some() {
			yeet!(CreateClientError::UriFragment.into())
		}
	}

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
		yeet!(CreateClientError::NoSecret.into())
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
		.service(get_client_allowed_scopes)
		.service(get_client_default_scopes)
		.service(get_client_redirect_uris)
		.service(get_client_is_trusted)
		.service(create_client)
		.service(update_client)
		.service(update_client_alias)
		.service(update_client_type)
		.service(update_client_allowed_scopes)
		.service(update_client_default_scopes)
		.service(update_client_is_trusted)
		.service(update_client_redirect_uris)
		.service(update_client_secret)
}

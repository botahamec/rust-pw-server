use actix_web::http::{header, StatusCode};
use actix_web::{post, put, web, HttpResponse, ResponseError, Scope};
use raise::yeet;
use serde::Deserialize;
use sqlx::MySqlPool;
use thiserror::Error;
use uuid::Uuid;

use crate::models::User;
use crate::services::crypto::PasswordHash;
use crate::services::{db, id};

#[derive(Clone, Deserialize)]
struct UserRequest {
	username: Box<str>,
	password: Box<str>,
}

#[derive(Debug, Clone, Hash, Error)]
#[error("An account with the given username already exists.")]
struct UsernameTakenError {
	username: Box<str>,
}

impl ResponseError for UsernameTakenError {
	fn status_code(&self) -> StatusCode {
		StatusCode::CONFLICT
	}
}

#[post("/")]
async fn create_user(
	body: web::Json<UserRequest>,
	conn: web::Data<MySqlPool>,
) -> Result<HttpResponse, UsernameTakenError> {
	let conn = conn.get_ref();

	let user_id = id::new_user_id(conn).await.unwrap();
	let username = body.username.clone();
	let password = PasswordHash::new(&body.password).unwrap();

	if db::username_is_used(conn, &body.username).await.unwrap() {
		yeet!(UsernameTakenError { username });
	}

	let user = User {
		user_id,
		username,
		password,
	};

	db::new_user(conn, &user).await.unwrap();

	let response = HttpResponse::Created()
		.insert_header((header::LOCATION, format!("users/{user_id}")))
		.finish();
	Ok(response)
}

#[put("/{user_id}")]
async fn update_user(
	user_id: web::Path<Uuid>,
	body: web::Json<UserRequest>,
	conn: web::Data<MySqlPool>,
) -> Result<HttpResponse, UsernameTakenError> {
	let conn = conn.get_ref();

	let user_id = user_id.to_owned();
	let username = body.username.clone();
	let password = PasswordHash::new(&body.password).unwrap();

	let old_username = db::get_username(conn, user_id).await.unwrap().unwrap();
	if username != old_username && db::username_is_used(conn, &body.username).await.unwrap() {
		yeet!(UsernameTakenError { username })
	}

	let user = User {
		user_id,
		username,
		password,
	};

	db::update_user(conn, &user).await.unwrap();

	let response = HttpResponse::NoContent()
		.insert_header((header::LOCATION, format!("users/{user_id}")))
		.finish();

	Ok(response)
}

#[put("/{user_id}/username")]
async fn update_username(
	user_id: web::Path<Uuid>,
	body: web::Json<Box<str>>,
	conn: web::Data<MySqlPool>,
) -> Result<HttpResponse, UsernameTakenError> {
	let conn = conn.get_ref();

	let user_id = user_id.to_owned();
	let username = body.clone();

	let old_username = db::get_username(conn, user_id).await.unwrap().unwrap();
	if username != old_username && db::username_is_used(conn, &body).await.unwrap() {
		yeet!(UsernameTakenError { username })
	}

	db::update_username(conn, user_id, &body).await.unwrap();

	let response = HttpResponse::NoContent()
		.insert_header((header::LOCATION, format!("users/{user_id}/username")))
		.finish();

	Ok(response)
}

#[put("/{user_id}/password")]
async fn update_password(
	user_id: web::Path<Uuid>,
	body: web::Json<Box<str>>,
	conn: web::Data<MySqlPool>,
) -> HttpResponse {
	let conn = conn.get_ref();

	let user_id = user_id.to_owned();
	let password = PasswordHash::new(&body).unwrap();

	db::update_password(conn, user_id, &password).await.unwrap();

	let response = HttpResponse::NoContent()
		.insert_header((header::LOCATION, format!("users/{user_id}/password")))
		.finish();

	response
}

pub fn service() -> Scope {
	web::scope("/users")
		.service(create_user)
		.service(update_user)
		.service(update_username)
		.service(update_password)
}

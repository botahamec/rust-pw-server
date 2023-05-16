use actix_web::http::{header, StatusCode};
use actix_web::{get, post, put, web, HttpResponse, ResponseError, Scope};
use raise::yeet;
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;
use thiserror::Error;
use uuid::Uuid;

use crate::models::User;
use crate::services::crypto::PasswordHash;
use crate::services::{db, id};

/// Just a username. No password hash, because that'd be tempting fate.
#[derive(Debug, Clone, Serialize)]
struct UserResponse {
	id: Uuid,
	username: Box<str>,
}

impl From<User> for UserResponse {
	fn from(user: User) -> Self {
		Self {
			id: user.id,
			username: user.username,
		}
	}
}

#[derive(Debug, Clone, Deserialize)]
struct SearchUsers {
	username: Option<Box<str>>,
	limit: Option<u32>,
	offset: Option<u32>,
}

#[get("")]
async fn search_users(params: web::Query<SearchUsers>, conn: web::Data<MySqlPool>) -> HttpResponse {
	let conn = conn.get_ref();

	let username = params.username.clone().unwrap_or_default();
	let offset = params.offset.unwrap_or_default();

	let results: Box<[UserResponse]> = if let Some(limit) = params.limit {
		db::search_users_limit(conn, &username, offset, limit)
			.await
			.unwrap()
			.iter()
			.cloned()
			.map(|u| u.into())
			.collect()
	} else {
		db::search_users(conn, &username)
			.await
			.unwrap()
			.into_iter()
			.skip(offset as usize)
			.cloned()
			.map(|u| u.into())
			.collect()
	};

	let response = HttpResponse::Ok().json(results);
	response
}

#[derive(Debug, Clone, Error)]
#[error("No user with the given ID exists")]
struct UserNotFoundError {
	user_id: Uuid,
}

impl ResponseError for UserNotFoundError {
	fn status_code(&self) -> StatusCode {
		StatusCode::NOT_FOUND
	}
}

#[get("/{user_id}")]
async fn get_user(
	user_id: web::Path<Uuid>,
	conn: web::Data<MySqlPool>,
) -> Result<HttpResponse, UserNotFoundError> {
	let conn = conn.get_ref();

	let user_id = user_id.to_owned();
	let user = db::get_user(conn, user_id).await.unwrap();

	let Some(user) = user else {
		yeet!(UserNotFoundError {user_id});
	};

	let response: UserResponse = user.into();
	let response = HttpResponse::Ok().json(response);
	Ok(response)
}

#[get("/{user_id}/username")]
async fn get_username(
	user_id: web::Path<Uuid>,
	conn: web::Data<MySqlPool>,
) -> Result<HttpResponse, UserNotFoundError> {
	let conn = conn.get_ref();

	let user_id = user_id.to_owned();
	let username = db::get_username(conn, user_id).await.unwrap();

	let Some(username) = username else {
		yeet!(UserNotFoundError { user_id });
	};

	let response = HttpResponse::Ok().json(username);
	Ok(response)
}

/// A request to create or update user information
#[derive(Debug, Clone, Deserialize)]
struct UserRequest {
	username: Box<str>,
	password: Box<str>,
}

#[derive(Debug, Clone, Error)]
#[error("An account with the given username already exists.")]
struct UsernameTakenError {
	username: Box<str>,
}

impl ResponseError for UsernameTakenError {
	fn status_code(&self) -> StatusCode {
		StatusCode::CONFLICT
	}
}

#[post("")]
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
		id: user_id,
		username,
		password,
	};

	db::new_user(conn, &user).await.unwrap();

	let response = HttpResponse::Created()
		.insert_header((header::LOCATION, format!("users/{user_id}")))
		.finish();
	Ok(response)
}

#[derive(Debug, Clone, Error)]
enum UpdateUserError {
	#[error(transparent)]
	UsernameTaken(#[from] UsernameTakenError),
	#[error(transparent)]
	NotFound(#[from] UserNotFoundError),
}

impl ResponseError for UpdateUserError {
	fn status_code(&self) -> StatusCode {
		match self {
			Self::UsernameTaken(..) => StatusCode::CONFLICT,
			Self::NotFound(..) => StatusCode::NOT_FOUND,
		}
	}
}

#[put("/{user_id}")]
async fn update_user(
	user_id: web::Path<Uuid>,
	body: web::Json<UserRequest>,
	conn: web::Data<MySqlPool>,
) -> Result<HttpResponse, UpdateUserError> {
	let conn = conn.get_ref();

	let user_id = user_id.to_owned();
	let username = body.username.clone();
	let password = PasswordHash::new(&body.password).unwrap();

	let old_username = db::get_username(conn, user_id).await.unwrap().unwrap();
	if username != old_username && db::username_is_used(conn, &body.username).await.unwrap() {
		yeet!(UsernameTakenError { username }.into())
	}

	if !db::user_id_exists(conn, user_id).await.unwrap() {
		yeet!(UserNotFoundError { user_id }.into())
	}

	let user = User {
		id: user_id,
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
) -> Result<HttpResponse, UpdateUserError> {
	let conn = conn.get_ref();

	let user_id = user_id.to_owned();
	let username = body.clone();

	let old_username = db::get_username(conn, user_id).await.unwrap().unwrap();
	if username != old_username && db::username_is_used(conn, &body).await.unwrap() {
		yeet!(UsernameTakenError { username }.into())
	}

	if !db::user_id_exists(conn, user_id).await.unwrap() {
		yeet!(UserNotFoundError { user_id }.into())
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
) -> Result<HttpResponse, UserNotFoundError> {
	let conn = conn.get_ref();

	let user_id = user_id.to_owned();
	let password = PasswordHash::new(&body).unwrap();

	if !db::user_id_exists(conn, user_id).await.unwrap() {
		yeet!(UserNotFoundError { user_id })
	}

	db::update_password(conn, user_id, &password).await.unwrap();

	let response = HttpResponse::NoContent().finish();
	Ok(response)
}

pub fn service() -> Scope {
	web::scope("/users")
		.service(search_users)
		.service(get_user)
		.service(get_username)
		.service(create_user)
		.service(update_user)
		.service(update_username)
		.service(update_password)
}

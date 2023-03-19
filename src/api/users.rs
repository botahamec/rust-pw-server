use actix_web::http::{header, StatusCode};
use actix_web::{post, web, HttpResponse, ResponseError, Scope};
use raise::yeet;
use serde::Deserialize;
use sqlx::MySqlPool;
use thiserror::Error;

use crate::models::User;
use crate::services::crypto::PasswordHash;
use crate::services::db::{new_user, username_is_used};
use crate::services::id::new_user_id;

#[derive(Clone, Deserialize)]
struct CreateUser {
	username: Box<str>,
	password: Box<str>,
}

#[derive(Debug, Clone, Hash, Error)]
#[error("An account with the given username already exists.")]
struct CreateUserError {
	username: Box<str>,
}

impl ResponseError for CreateUserError {
	fn status_code(&self) -> StatusCode {
		StatusCode::CONFLICT
	}
}

#[post("")]
async fn create_user(
	body: web::Json<CreateUser>,
	conn: web::Data<MySqlPool>,
) -> Result<HttpResponse, CreateUserError> {
	let conn = conn.get_ref();

	let user_id = new_user_id(conn).await.unwrap();
	let username = body.username.clone();
	let password = PasswordHash::new(&body.password).unwrap();

	if username_is_used(conn, &body.username).await.unwrap() {
		yeet!(CreateUserError { username });
	}

	let user = User {
		user_id,
		username,
		password,
	};

	new_user(conn, user).await.unwrap();

	let response = HttpResponse::Created()
		.insert_header((header::LOCATION, format!("users/{user_id}")))
		.finish();
	Ok(response)
}

pub fn service() -> Scope {
	web::scope("users").service(create_user)
}

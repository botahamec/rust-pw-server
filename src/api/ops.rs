use actix_web::{http::StatusCode, post, web, HttpResponse, ResponseError, Scope};
use raise::yeet;
use serde::Deserialize;
use sqlx::MySqlPool;
use thiserror::Error;

use crate::services::db;

/// A request to login
#[derive(Debug, Clone, Deserialize)]
struct LoginRequest {
	username: Box<str>,
	password: Box<str>,
}

/// An error occurred when authenticating, because either the username or
/// password was invalid.
#[derive(Debug, Clone, Error)]
enum LoginFailure {
	#[error("No user found with the given username")]
	UserNotFound { username: Box<str> },
	#[error("The given password is incorrect")]
	IncorrectPassword { username: Box<str> },
}

impl ResponseError for LoginFailure {
	fn status_code(&self) -> actix_web::http::StatusCode {
		match self {
			Self::UserNotFound { .. } => StatusCode::NOT_FOUND,
			Self::IncorrectPassword { .. } => StatusCode::UNAUTHORIZED,
		}
	}
}

/// Returns `200` if login was successful.
/// Returns `404` if the username is invalid.
/// Returns `401` if the password was invalid.
#[post("/login")]
async fn login(
	body: web::Json<LoginRequest>,
	conn: web::Data<MySqlPool>,
) -> Result<HttpResponse, LoginFailure> {
	let conn = conn.get_ref();

	let user = db::get_user_by_username(conn, &body.username)
		.await
		.unwrap();
	let Some(user) = user else {
		yeet!(LoginFailure::UserNotFound{ username: body.username.clone() });
	};

	let good_password = user.check_password(&body.password).unwrap();
	let response = if good_password {
		HttpResponse::Ok().finish()
	} else {
		yeet!(LoginFailure::IncorrectPassword {
			username: body.username.clone()
		});
	};
	Ok(response)
}

pub fn service() -> Scope {
	web::scope("").service(login)
}

use std::ops::Deref;
use std::str::FromStr;

use actix_web::http::header;
use actix_web::{get, post, web, HttpRequest, HttpResponse, ResponseError, Scope};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;
use tera::Tera;
use thiserror::Error;
use unic_langid::subtags::Language;
use url::Url;

use crate::resources::{languages, templates};
use crate::scopes;
use crate::services::{authorization, db, jwt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResponseType {
	Code,
	Token,
	#[serde(other)]
	Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationParameters {
	response_type: ResponseType,
	client_id: Box<str>,
	redirect_uri: Option<Url>,
	scope: Option<Box<str>>,
	state: Option<Box<str>>,
}

#[derive(Clone, Deserialize)]
struct AuthorizeCredentials {
	username: Box<str>,
	password: Box<str>,
}

#[derive(Clone, Serialize)]
struct CodeResponse {
	code: Box<str>,
	state: Option<Box<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
enum AuthorizeErrorType {
	InvalidRequest,
	UnauthorizedClient,
	AccessDenied,
	UnsupportedResponseType,
	InvalidScope,
	ServerError,
	TemporarilyUnavailable,
}

#[derive(Debug, Clone, Error)]
#[error("{error_description}")]
struct AuthorizeError {
	error: AuthorizeErrorType,
	error_description: Box<str>,
	// TODO error uri
	state: Option<Box<str>>,
	redirect_uri: Url,
}

impl AuthorizeError {
	fn no_scope(redirect_uri: Url, state: Option<Box<str>>) -> Self {
		Self {
			error: AuthorizeErrorType::InvalidScope,
			error_description: Box::from(
				"No scope was provided, and the client does not have a default scope",
			),
			state,
			redirect_uri,
		}
	}
}

impl ResponseError for AuthorizeError {
	fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
		let error = serde_variant::to_variant_name(&self.error).unwrap_or_default();
		let mut url = self.redirect_uri.clone();
		url.query_pairs_mut()
			.append_pair("error", error)
			.append_pair("error_description", &self.error_description);

		if let Some(state) = &self.state {
			url.query_pairs_mut().append_pair("state", &state);
		}

		HttpResponse::Found()
			.insert_header((header::LOCATION, url.as_str()))
			.finish()
	}
}

#[post("/authorize")]
async fn authorize(
	db: web::Data<MySqlPool>,
	req: web::Query<AuthorizationParameters>,
	credentials: web::Json<AuthorizeCredentials>,
) -> HttpResponse {
	// TODO use sessions to verify that the request was previously validated
	let db = db.get_ref();
	let Some(client_id) = db::get_client_id_by_alias(db, &req.client_id).await.unwrap() else {
		todo!("client not found")
	};
	let self_id = Url::parse("www.google.com").unwrap(); // TODO find the actual value
	let state = req.state.clone();

	// get redirect uri
	let redirect_uri = if let Some(redirect_uri) = &req.redirect_uri {
		redirect_uri.clone()
	} else {
		let redirect_uris = db::get_client_redirect_uris(db, client_id).await.unwrap();
		if redirect_uris.len() != 1 {
			todo!("no redirect uri");
		}

		redirect_uris[0].clone()
	};

	// authenticate user
	let Some(user) = db::get_user_by_username(db, &credentials.username).await.unwrap() else {
		todo!("bad username")
	};
	if !user.check_password(&credentials.password).unwrap() {
		todo!("bad password")
	}

	// get scope
	let scope = if let Some(scope) = &req.scope {
		scope.clone()
	} else {
		let default_scopes = db::get_client_default_scopes(db, client_id)
			.await
			.unwrap()
			.unwrap();
		let Some(scope) = default_scopes else {
			return AuthorizeError::no_scope(redirect_uri, state).error_response()
		};
		scope
	};

	match req.response_type {
		ResponseType::Code => {
			// create auth code
			let code = jwt::Claims::auth_code(db, self_id, client_id, &scope, &redirect_uri)
				.await
				.unwrap();
			let code = code.to_jwt().unwrap();
			let response = CodeResponse { code, state };

			HttpResponse::Ok().json(response)
		}
		ResponseType::Token => todo!(),
		_ => todo!("unsupported response type"),
	}
}

#[get("/authorize")]
async fn authorize_page(
	db: web::Data<MySqlPool>,
	tera: web::Data<Tera>,
	translations: web::Data<languages::Translations>,
	request: HttpRequest,
) -> HttpResponse {
	let params = request.query_string();
	let params = serde_urlencoded::from_str::<AuthorizationParameters>(params);
	let Ok(params) = params else {
		todo!("invalid request")
	};

	let db = db.get_ref();
	let Some(client_id) = db::get_client_id_by_alias(db, &params.client_id).await.unwrap() else {
		todo!("client not found")
	};

	// verify scope
	let Some(allowed_scopes) = db::get_client_allowed_scopes(db, client_id).await.unwrap() else {
		todo!("client not found")
	};

	let scope = if let Some(scope) = &params.scope {
		scope.clone()
	} else {
		let default_scopes = db::get_client_default_scopes(db, client_id)
			.await
			.unwrap()
			.unwrap();
		let Some(scope) = default_scopes else {
			todo!("invalid request")
		};
		scope
	};

	if !scopes::is_subset_of(&scope, &allowed_scopes) {
		todo!("access_denied")
	}

	// verify redirect uri
	if let Some(redirect_uri) = &params.redirect_uri {
		if !db::client_has_redirect_uri(db, client_id, redirect_uri)
			.await
			.unwrap()
		{
			todo!("access denied")
		}
	} else {
		let redirect_uris = db::get_client_redirect_uris(db, client_id).await.unwrap();
		if redirect_uris.len() != 1 {
			todo!("must have redirect uri")
		}
	}

	// verify response type
	if params.response_type == ResponseType::Unsupported {
		todo!("unsupported response type")
	}

	// TODO find a better way of doing languages
	let language = Language::from_str("en").unwrap();
	let page =
		templates::login_page(&tera, &params, language, translations.get_ref().clone()).unwrap();
	HttpResponse::Ok().content_type("text/html").body(page)
}

#[derive(Clone, Deserialize)]
#[serde(tag = "grant_type")]
#[serde(rename_all = "snake_case")]
enum GrantType {
	AuthorizationCode {
		code: Box<str>,
		redirect_uri: Url,
		#[serde(rename = "client_id")]
		client_alias: Box<str>,
	},
	Password {
		username: Box<str>,
		password: Box<str>,
		scope: Option<Box<str>>,
	},
	ClientCredentials {
		scope: Option<Box<str>>,
	},
}

#[derive(Clone, Deserialize)]
struct TokenRequest {
	#[serde(flatten)]
	grant_type: GrantType,
	// TODO support optional client credentials in here
}

#[derive(Clone, Serialize)]
struct TokenResponse {
	access_token: Box<str>,
	token_type: Box<str>,
	expires_in: i64,
	refresh_token: Box<str>,
	scope: Box<str>,
}

#[post("/token")]
async fn token(
	db: web::Data<MySqlPool>,
	req: web::Bytes,
	authorization: Option<web::Header<authorization::BasicAuthorization>>,
) -> HttpResponse {
	// TODO protect against brute force attacks
	let db = db.get_ref();
	let request = serde_json::from_slice::<TokenRequest>(&req);
	let Ok(request) = request else {
		todo!("invalid request")
	};

	let self_id = Url::parse("www.google.com").unwrap(); // TODO find the actual value
	let duration = Duration::hours(1);
	let token_type = Box::from("bearer");
	let cache_control = header::CacheControl(vec![header::CacheDirective::NoStore]);

	match request.grant_type {
		GrantType::AuthorizationCode {
			code,
			redirect_uri,
			client_alias,
		} => {
			let Some(client_id) = db::get_client_id_by_alias(db, &client_alias).await.unwrap() else {
				todo!("client not found")
			};

			let Ok(claims) = jwt::verify_auth_code(db, &code, self_id.clone(), client_id, redirect_uri).await else {
				todo!("invalid code");
			};

			// verify client, if the client has credentials
			if let Some(hash) = db::get_client_secret(db, client_id).await.unwrap() {
				let Some(authorization) = authorization else {
					todo!("no client credentials")
				};

				if authorization.username() != client_alias.deref() {
					todo!("bad username")
				}
				if !hash.check_password(authorization.password()).unwrap() {
					todo!("bad password")
				}
			}

			let access_token = jwt::Claims::access_token(
				db,
				claims.id(),
				self_id,
				client_id,
				duration,
				claims.scopes(),
			)
			.await
			.unwrap();

			let expires_in = access_token.expires_in();
			let refresh_token = jwt::Claims::refresh_token(db, &access_token).await.unwrap();
			let scope = access_token.scopes().into();

			let access_token = access_token.to_jwt().unwrap();
			let refresh_token = refresh_token.to_jwt().unwrap();

			let response = TokenResponse {
				access_token,
				token_type,
				expires_in,
				refresh_token,
				scope,
			};
			HttpResponse::Ok()
				.insert_header(cache_control)
				.insert_header((header::PRAGMA, "no-cache"))
				.json(response)
		}
		GrantType::Password {
			username,
			password,
			scope,
		} => todo!(),
		GrantType::ClientCredentials { scope } => todo!(),
	}
}

pub fn service() -> Scope {
	web::scope("/oauth")
		.service(authorize_page)
		.service(authorize)
		.service(token)
}

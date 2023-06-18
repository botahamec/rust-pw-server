use std::ops::Deref;
use std::str::FromStr;

use actix_web::http::{header, StatusCode};
use actix_web::{
	get, post, web, HttpRequest, HttpResponse, HttpResponseBuilder, ResponseError, Scope,
};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;
use tera::Tera;
use thiserror::Error;
use unic_langid::subtags::Language;
use url::Url;
use uuid::Uuid;

use crate::models::client::ClientType;
use crate::resources::{languages, templates};
use crate::scopes;
use crate::services::jwt::VerifyJwtError;
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
struct AuthCodeResponse {
	code: Box<str>,
	state: Option<Box<str>>,
}

#[derive(Clone, Serialize)]
struct AuthTokenResponse {
	access_token: Box<str>,
	token_type: &'static str,
	expires_in: i64,
	scope: Box<str>,
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

#[derive(Debug, Clone, Error, Serialize)]
#[error("{error_description}")]
struct AuthorizeError {
	error: AuthorizeErrorType,
	error_description: Box<str>,
	// TODO error uri
	state: Option<Box<str>>,
	#[serde(skip)]
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

	fn unsupported_response_type(redirect_uri: Url, state: Option<Box<str>>) -> Self {
		Self {
			error: AuthorizeErrorType::UnsupportedResponseType,
			error_description: Box::from("The given response type is not supported"),
			state,
			redirect_uri,
		}
	}

	fn invalid_scope(redirect_uri: Url, state: Option<Box<str>>) -> Self {
		Self {
			error: AuthorizeErrorType::InvalidScope,
			error_description: Box::from("The given scope exceeds what the client is allowed"),
			state,
			redirect_uri,
		}
	}
}

impl ResponseError for AuthorizeError {
	fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
		let query = Some(serde_urlencoded::to_string(self).unwrap());
		let query = query.as_deref();
		let mut url = self.redirect_uri.clone();
		url.set_query(query);

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
	tera: web::Data<Tera>,
	translations: web::Data<languages::Translations>,
) -> HttpResponse {
	// TODO use sessions to verify that the request was previously validated
	// TODO handle internal server error
	let db = db.get_ref();
	let Some(client_id) = db::get_client_id_by_alias(db, &req.client_id).await.unwrap() else {
		// TODO find a better way of doing languages
		let language = Language::from_str("en").unwrap();
		let translations = translations.get_ref().clone();
		let page = templates::error_page(&tera, language, translations, templates::ErrorPage::ClientNotFound).unwrap();
		return HttpResponse::NotFound().content_type("text/html").body(page);
	};
	let self_id = Url::parse("www.google.com").unwrap(); // TODO find the actual value
	let state = req.state.clone();

	// get redirect uri
	let mut redirect_uri = if let Some(redirect_uri) = &req.redirect_uri {
		redirect_uri.clone()
	} else {
		let redirect_uris = db::get_client_redirect_uris(db, client_id).await.unwrap();
		if redirect_uris.len() != 1 {
			let language = Language::from_str("en").unwrap();
			let translations = translations.get_ref().clone();
			let page = templates::error_page(
				&tera,
				language,
				translations,
				templates::ErrorPage::MissingRedirectUri,
			)
			.unwrap();
			return HttpResponse::NotFound()
				.content_type("text/html")
				.body(page);
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

			let response = AuthCodeResponse { code, state };
			let query = Some(serde_urlencoded::to_string(response).unwrap());
			let query = query.as_deref();
			redirect_uri.set_query(query);

			HttpResponse::Found()
				.append_header((header::LOCATION, redirect_uri.as_str()))
				.finish()
		}
		ResponseType::Token => {
			// create access token
			let duration = Duration::hours(1);
			let access_token =
				jwt::Claims::access_token(db, None, self_id, client_id, duration, &scope)
					.await
					.unwrap();

			let access_token = access_token.to_jwt().unwrap();
			let expires_in = duration.num_seconds();
			let token_type = "bearer";
			let response = AuthTokenResponse {
				access_token,
				expires_in,
				token_type,
				scope,
				state,
			};

			let fragment = Some(serde_urlencoded::to_string(response).unwrap());
			let fragment = fragment.as_deref();
			redirect_uri.set_fragment(fragment);

			HttpResponse::Found()
				.append_header((header::LOCATION, redirect_uri.as_str()))
				.finish()
		}
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
	// TODO handle internal server error
	let language = Language::from_str("en").unwrap();
	let translations = translations.get_ref().clone();

	let params = request.query_string();
	let params = serde_urlencoded::from_str::<AuthorizationParameters>(params);
	let Ok(params) = params else {
		let page = templates::error_page(
			&tera,
			language,
			translations,
			templates::ErrorPage::InvalidRequest,
		)
		.unwrap();
		return HttpResponse::BadRequest()
			.content_type("text/html")
			.body(page);
	};

	let db = db.get_ref();
	let Some(client_id) = db::get_client_id_by_alias(db, &params.client_id).await.unwrap() else {
		let page = templates::error_page(
			&tera,
			language,
			translations,
			templates::ErrorPage::ClientNotFound,
		)
		.unwrap();
		return HttpResponse::NotFound()
			.content_type("text/html")
			.body(page);
	};

	// verify scope
	let allowed_scopes = db::get_client_allowed_scopes(db, client_id)
		.await
		.unwrap()
		.unwrap();

	// verify redirect uri
	let redirect_uri: Url;
	if let Some(uri) = &params.redirect_uri {
		redirect_uri = uri.clone();
		if !db::client_has_redirect_uri(db, client_id, &redirect_uri)
			.await
			.unwrap()
		{
			let page = templates::error_page(
				&tera,
				language,
				translations,
				templates::ErrorPage::InvalidRedirectUri,
			)
			.unwrap();
			return HttpResponse::BadRequest()
				.content_type("text/html")
				.body(page);
		}
	} else {
		let redirect_uris = db::get_client_redirect_uris(db, client_id).await.unwrap();
		if redirect_uris.len() != 1 {
			let page = templates::error_page(
				&tera,
				language,
				translations,
				templates::ErrorPage::MissingRedirectUri,
			)
			.unwrap();
			return HttpResponse::NotFound()
				.content_type("text/html")
				.body(page);
		}

		redirect_uri = redirect_uris.get(0).unwrap().clone();
	}

	let scope = if let Some(scope) = &params.scope {
		scope.clone()
	} else {
		let default_scopes = db::get_client_default_scopes(db, client_id)
			.await
			.unwrap()
			.unwrap();
		let Some(scope) = default_scopes else {
			return AuthorizeError::no_scope(redirect_uri, params.state).error_response();
		};
		scope
	};

	if !scopes::is_subset_of(&scope, &allowed_scopes) {
		return AuthorizeError::invalid_scope(redirect_uri, params.state).error_response();
	}

	// verify response type
	if params.response_type == ResponseType::Unsupported {
		return AuthorizeError::unsupported_response_type(redirect_uri, params.state)
			.error_response();
	}

	// TODO find a better way of doing languages
	let language = Language::from_str("en").unwrap();
	let page = templates::login_page(&tera, &params, language, translations).unwrap();
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
	RefreshToken {
		refresh_token: Box<str>,
		scope: Option<Box<str>>,
	},
	#[serde(other)]
	Unsupported,
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
	refresh_token: Option<Box<str>>,
	scope: Box<str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum TokenErrorType {
	InvalidRequest,
	InvalidClient,
	InvalidGrant,
	UnauthorizedClient,
	UnsupportedGrantType,
	InvalidScope,
}

#[derive(Debug, Clone, Error, Serialize)]
#[error("{error_description}")]
struct TokenError {
	#[serde(skip)]
	status_code: StatusCode,
	error: TokenErrorType,
	error_description: Box<str>,
	// TODO error uri
}

impl TokenError {
	fn invalid_request() -> Self {
		// TODO make this description better, and all the other ones while you're at it
		Self {
			status_code: StatusCode::BAD_REQUEST,
			error: TokenErrorType::InvalidRequest,
			error_description: "Invalid request".into(),
		}
	}

	fn unsupported_grant_type() -> Self {
		Self {
			status_code: StatusCode::BAD_REQUEST,
			error: TokenErrorType::UnsupportedGrantType,
			error_description: "The given grant type is not supported".into(),
		}
	}

	fn bad_auth_code(error: VerifyJwtError) -> Self {
		Self {
			status_code: StatusCode::BAD_REQUEST,
			error: TokenErrorType::InvalidGrant,
			error_description: error.to_string().into_boxed_str(),
		}
	}

	fn no_authorization() -> Self {
		Self {
			status_code: StatusCode::UNAUTHORIZED,
			error: TokenErrorType::InvalidClient,
			error_description: Box::from(
				"Client credentials must be provided in the HTTP Authorization header",
			),
		}
	}

	fn client_not_found(alias: &str) -> Self {
		Self {
			status_code: StatusCode::UNAUTHORIZED,
			error: TokenErrorType::InvalidClient,
			error_description: format!("No client with the client id: {alias} was found")
				.into_boxed_str(),
		}
	}

	fn incorrect_client_secret() -> Self {
		Self {
			status_code: StatusCode::UNAUTHORIZED,
			error: TokenErrorType::InvalidClient,
			error_description: "The client secret is incorrect".into(),
		}
	}

	fn client_not_confidential(alias: &str) -> Self {
		Self {
			status_code: StatusCode::BAD_REQUEST,
			error: TokenErrorType::UnauthorizedClient,
			error_description: format!("Only a confidential client may be used with this endpoint. The {alias} client is a public client.")
				.into_boxed_str(),
		}
	}

	fn no_scope() -> Self {
		Self {
			status_code: StatusCode::BAD_REQUEST,
			error: TokenErrorType::InvalidScope,
			error_description: Box::from(
				"No scope was provided, and the client doesn't have a default scope",
			),
		}
	}

	fn excessive_scope() -> Self {
		Self {
			status_code: StatusCode::BAD_REQUEST,
			error: TokenErrorType::InvalidScope,
			error_description: Box::from(
				"The given scope exceeds what the client is allowed to have",
			),
		}
	}

	fn bad_refresh_token(err: VerifyJwtError) -> Self {
		Self {
			status_code: StatusCode::BAD_REQUEST,
			error: TokenErrorType::InvalidGrant,
			error_description: err.to_string().into_boxed_str(),
		}
	}
}

impl ResponseError for TokenError {
	fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
		let cache_control = header::CacheControl(vec![header::CacheDirective::NoStore]);

		let mut builder = HttpResponseBuilder::new(self.status_code);

		if self.status_code.as_u16() == 401 {
			builder.insert_header((header::WWW_AUTHENTICATE, "Basic charset=\"UTF-8\""));
		}

		builder
			.insert_header(cache_control)
			.insert_header((header::PRAGMA, "no-cache"))
			.json(self.clone())
	}
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
		return TokenError::invalid_request().error_response();
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
				return TokenError::client_not_found(&client_alias).error_response();
			};

			// validate auth code
			let claims =
				match jwt::verify_auth_code(db, &code, self_id.clone(), client_id, redirect_uri)
					.await
				{
					Ok(claims) => claims,
					Err(err) => {
						let err = err.unwrap();
						return TokenError::bad_auth_code(err).error_response();
					}
				};

			// verify client, if the client has credentials
			if let Some(hash) = db::get_client_secret(db, client_id).await.unwrap() {
				let Some(authorization) = authorization else {
					return TokenError::no_authorization().error_response();
				};

				if authorization.username() != client_alias.deref() {
					todo!("bad username")
				}
				if !hash.check_password(authorization.password()).unwrap() {
					return TokenError::incorrect_client_secret().error_response();
				}
			}

			let access_token = jwt::Claims::access_token(
				db,
				Some(claims.id()),
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
			let refresh_token = Some(refresh_token.to_jwt().unwrap());

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
		GrantType::ClientCredentials { scope } => {
			let Some(authorization) = authorization else {
				return TokenError::no_authorization().error_response();
			};
			let client_alias = authorization.username();
			let Some(client_id) = db::get_client_id_by_alias(db, client_alias).await.unwrap() else {
				return TokenError::client_not_found(client_alias).error_response();
			};

			let ty = db::get_client_type(db, client_id).await.unwrap().unwrap();
			if ty != ClientType::Confidential {
				return TokenError::client_not_confidential(client_alias).error_response();
			}

			// verify client
			let hash = db::get_client_secret(db, client_id).await.unwrap().unwrap();
			if !hash.check_password(authorization.password()).unwrap() {
				return TokenError::incorrect_client_secret().error_response();
			}

			// verify scope
			let allowed_scopes = db::get_client_allowed_scopes(db, client_id)
				.await
				.unwrap()
				.unwrap();
			let scope = if let Some(scope) = &scope {
				scope.clone()
			} else {
				let default_scopes = db::get_client_default_scopes(db, client_id)
					.await
					.unwrap()
					.unwrap();
				let Some(scope) = default_scopes else {
					return TokenError::no_scope().error_response();
				};
				scope
			};
			if !scopes::is_subset_of(&scope, &allowed_scopes) {
				return TokenError::excessive_scope().error_response();
			}

			let access_token =
				jwt::Claims::access_token(db, None, self_id, client_id, duration, &scope)
					.await
					.unwrap();

			let expires_in = access_token.expires_in();
			let scope = access_token.scopes().into();
			let access_token = access_token.to_jwt().unwrap();

			let response = TokenResponse {
				access_token,
				token_type,
				expires_in,
				refresh_token: None,
				scope,
			};
			HttpResponse::Ok()
				.insert_header(cache_control)
				.insert_header((header::PRAGMA, "no-cache"))
				.json(response)
		}
		GrantType::RefreshToken {
			refresh_token,
			scope,
		} => {
			let client_id: Option<Uuid>;
			if let Some(authorization) = authorization {
				let client_alias = authorization.username();
				let Some(id) = db::get_client_id_by_alias(db, client_alias).await.unwrap() else {
					return TokenError::client_not_found(client_alias).error_response();
				};
				client_id = Some(id);
			} else {
				client_id = None;
			}

			let claims =
				match jwt::verify_refresh_token(db, &refresh_token, self_id, client_id).await {
					Ok(claims) => claims,
					Err(e) => {
						let e = e.unwrap();
						return TokenError::bad_refresh_token(e).error_response();
					}
				};

			let scope = if let Some(scope) = scope {
				if !scopes::is_subset_of(&scope, claims.scopes()) {
					return TokenError::excessive_scope().error_response();
				}

				scope
			} else {
				claims.scopes().into()
			};

			let exp_time = Duration::hours(1);
			let access_token = jwt::Claims::refreshed_access_token(db, &claims, exp_time)
				.await
				.unwrap();
			let refresh_token = jwt::Claims::refresh_token(db, &claims).await.unwrap();

			let access_token = access_token.to_jwt().unwrap();
			let refresh_token = Some(refresh_token.to_jwt().unwrap());
			let expires_in = exp_time.num_seconds();

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
		_ => TokenError::unsupported_grant_type().error_response(),
	}
}

pub fn service() -> Scope {
	web::scope("/oauth")
		.service(authorize_page)
		.service(authorize)
		.service(token)
}

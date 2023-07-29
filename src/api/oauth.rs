use std::ops::Deref;
use std::str::FromStr;

use actix_web::http::{header, StatusCode};
use actix_web::{
	get, post, web, HttpRequest, HttpResponse, HttpResponseBuilder, ResponseError, Scope,
};
use chrono::Duration;
use exun::{Expect, RawUnexpected, ResultErrorExt, UnexpectedError};
use raise::yeet;
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
use crate::services::{authorization, brute_force_detection, config, db, jwt};

const REALLY_BAD_ERROR_PAGE: &str = "<!DOCTYPE html><html><head><title>Internal Server Error</title></head><body>Internal Server Error</body></html>";

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
#[serde(rename_all = "snake_case")]
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

	fn internal_server_error(redirect_uri: Url, state: Option<Box<str>>) -> Self {
		Self {
			error: AuthorizeErrorType::ServerError,
			error_description: "An unexpected error occurred".into(),
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

fn error_page(
	tera: &Tera,
	translations: &languages::Translations,
	error: templates::ErrorPage,
) -> Result<String, RawUnexpected> {
	// TODO find a better way of doing languages
	let language = Language::from_str("en").unwrap();
	let translations = translations.clone();
	let page = templates::error_page(&tera, language, translations, error)?;
	Ok(page)
}

async fn get_redirect_uri(
	redirect_uri: &Option<Url>,
	db: &MySqlPool,
	client_id: Uuid,
) -> Result<Url, Expect<templates::ErrorPage>> {
	if let Some(uri) = &redirect_uri {
		let redirect_uri = uri.clone();
		if !db::client_has_redirect_uri(db, client_id, &redirect_uri)
			.await
			.map_err(|e| UnexpectedError::from(e))
			.unexpect()?
		{
			yeet!(Expect::Expected(templates::ErrorPage::InvalidRedirectUri));
		}

		Ok(redirect_uri)
	} else {
		let redirect_uris = db::get_client_redirect_uris(db, client_id)
			.await
			.map_err(|e| UnexpectedError::from(e))
			.unexpect()?;
		if redirect_uris.len() != 1 {
			yeet!(Expect::Expected(templates::ErrorPage::MissingRedirectUri));
		}

		Ok(redirect_uris.get(0).unwrap().clone())
	}
}

async fn get_scope(
	scope: &Option<Box<str>>,
	db: &MySqlPool,
	client_id: Uuid,
	redirect_uri: &Url,
	state: &Option<Box<str>>,
) -> Result<Box<str>, Expect<AuthorizeError>> {
	let scope = if let Some(scope) = &scope {
		scope.clone()
	} else {
		let default_scopes = db::get_client_default_scopes(db, client_id)
			.await
			.unwrap()
			.unwrap();
		let Some(scope) = default_scopes else {
			yeet!(AuthorizeError::no_scope(redirect_uri.clone(), state.clone()).into())
		};
		scope
	};

	// verify scope is valid
	let allowed_scopes = db::get_client_allowed_scopes(db, client_id)
		.await
		.unwrap()
		.unwrap();
	if !scopes::is_subset_of(&scope, &allowed_scopes) {
		yeet!(AuthorizeError::invalid_scope(redirect_uri.clone(), state.clone()).into());
	}

	Ok(scope)
}

async fn authenticate_user(
	db: &MySqlPool,
	username: &str,
	password: &str,
) -> Result<Option<Uuid>, RawUnexpected> {
	let Some(user) = db::get_user_by_username(db, username).await? else {
		return Ok(None);
	};

	if user.check_password(password)? {
		Ok(Some(user.id))
	} else {
		Ok(None)
	}
}

#[post("/authorize")]
async fn authorize(
	db: web::Data<MySqlPool>,
	http_req: HttpRequest,
	req: web::Query<AuthorizationParameters>,
	credentials: web::Form<AuthorizeCredentials>,
	tera: web::Data<Tera>,
	translations: web::Data<languages::Translations>,
) -> Result<HttpResponse, AuthorizeError> {
	let db = db.get_ref();
	let Ok(client_id) = db::get_client_id_by_alias(db, &req.client_id).await else {
		let page = error_page(&tera, &translations, templates::ErrorPage::InternalServerError).unwrap_or_else(|_| String::from(REALLY_BAD_ERROR_PAGE));
		return Ok(HttpResponse::InternalServerError().content_type("text/html").body(page));
	};
	let Some(client_id) = client_id else {
		let page = error_page(&tera, &translations, templates::ErrorPage::ClientNotFound).unwrap_or_else(|_| String::from(REALLY_BAD_ERROR_PAGE));
		return Ok(HttpResponse::NotFound().content_type("text/html").body(page));
	};
	let Ok(config) = config::get_config() else {
		let page = error_page(&tera, &translations, templates::ErrorPage::InternalServerError).unwrap_or_else(|_| String::from(REALLY_BAD_ERROR_PAGE));
		return Ok(HttpResponse::InternalServerError().content_type("text/html").body(page));
	};
	let Some(addr) = http_req.peer_addr() else {
		let page = error_page(&tera, &translations, templates::ErrorPage::InternalServerError).unwrap_or_else(|_| String::from(REALLY_BAD_ERROR_PAGE));
		return Ok(HttpResponse::InternalServerError().content_type("text/html").body(page));
	};

	let self_id = config.url;
	let state = req.state.clone();

	// get redirect uri
	let mut redirect_uri = match get_redirect_uri(&req.redirect_uri, db, client_id).await {
		Ok(uri) => uri,
		Err(e) => {
			let e = e
				.expected()
				.unwrap_or(templates::ErrorPage::InternalServerError);
			let page = error_page(&tera, &translations, e)
				.unwrap_or_else(|_| String::from(REALLY_BAD_ERROR_PAGE));
			return Ok(HttpResponse::BadRequest()
				.content_type("text/html")
				.body(page));
		}
	};

	let internal_server_error =
		AuthorizeError::internal_server_error(redirect_uri.clone(), state.clone());

	// check for brute force attack
	let Ok(brute_force_detected) = brute_force_detection::brute_force_detected(db, &credentials.username, addr.ip()).await else {
		yeet!(internal_server_error.clone());
	};
	if brute_force_detected {
		let Ok(page) = error_page(&tera, &translations, templates::ErrorPage::TooManyRequests) else {
			yeet!(internal_server_error.clone());
		};
		return Ok(HttpResponse::TooManyRequests()
			.content_type("text/html")
			.body(page));
	}

	// authenticate user
	let Some(user_id) = authenticate_user(db, &credentials.username, &credentials.password)
		.await
		.unwrap() else // TODO remove unwrap
	{
		if db::add_failed_login_attempt(db, &credentials.username, addr.ip()).await.is_err() {
			yeet!(internal_server_error.clone());
		}
		let language = Language::from_str("en").unwrap();
		let translations = translations.get_ref().clone();
		let page = templates::login_error_page(&tera, &req, language, translations).unwrap_or_else(|_| String::from(REALLY_BAD_ERROR_PAGE));
		return Ok(HttpResponse::Ok().content_type("text/html").body(page));
	};

	// get scope
	let scope = match get_scope(&req.scope, db, client_id, &redirect_uri, &state).await {
		Ok(scope) => scope,
		Err(e) => {
			let e = e.expected().unwrap_or(internal_server_error);
			return Err(e);
		}
	};

	match req.response_type {
		ResponseType::Code => {
			// create auth code
			let code =
				jwt::Claims::auth_code(db, self_id, client_id, user_id, &scope, &redirect_uri)
					.await
					.map_err(|_| internal_server_error.clone())?;
			let code = code.to_jwt().map_err(|_| internal_server_error.clone())?;

			let response = AuthCodeResponse { code, state };
			let query =
				Some(serde_urlencoded::to_string(response).map_err(|_| internal_server_error)?);
			let query = query.as_deref();
			redirect_uri.set_query(query);

			Ok(HttpResponse::Found()
				.append_header((header::LOCATION, redirect_uri.as_str()))
				.finish())
		}
		ResponseType::Token => {
			// create access token
			let duration = Duration::hours(1);
			let access_token =
				jwt::Claims::access_token(db, None, self_id, client_id, user_id, duration, &scope)
					.await
					.map_err(|_| internal_server_error.clone())?;

			let access_token = access_token
				.to_jwt()
				.map_err(|_| internal_server_error.clone())?;
			let expires_in = duration.num_seconds();
			let token_type = "bearer";
			let response = AuthTokenResponse {
				access_token,
				expires_in,
				token_type,
				scope,
				state,
			};

			let fragment = Some(
				serde_urlencoded::to_string(response).map_err(|_| internal_server_error.clone())?,
			);
			let fragment = fragment.as_deref();
			redirect_uri.set_fragment(fragment);

			Ok(HttpResponse::Found()
				.append_header((header::LOCATION, redirect_uri.as_str()))
				.finish())
		}
		_ => Err(AuthorizeError::invalid_scope(redirect_uri, state)),
	}
}

#[get("/authorize")]
async fn authorize_page(
	db: web::Data<MySqlPool>,
	tera: web::Data<Tera>,
	translations: web::Data<languages::Translations>,
	request: HttpRequest,
) -> Result<HttpResponse, AuthorizeError> {
	let Ok(language) = Language::from_str("en") else {
		let page = String::from(REALLY_BAD_ERROR_PAGE);
		return Ok(HttpResponse::InternalServerError()
			.content_type("text/html")
			.body(page));
	};
	let translations = translations.get_ref().clone();

	let params = request.query_string();
	let params = serde_urlencoded::from_str::<AuthorizationParameters>(params);
	let Ok(params) = params else {
		let page = error_page(
			&tera,
			&translations,
			templates::ErrorPage::InvalidRequest,
		)
		.unwrap_or_else(|_| String::from(REALLY_BAD_ERROR_PAGE));
		return Ok(HttpResponse::BadRequest()
			.content_type("text/html")
			.body(page));
	};

	let db = db.get_ref();
	let Ok(client_id) = db::get_client_id_by_alias(db, &params.client_id).await else {
		let page = templates::error_page(
			&tera,
			language,
			translations,
			templates::ErrorPage::InternalServerError,
		)
		.unwrap_or_else(|_| String::from(REALLY_BAD_ERROR_PAGE));
		return Ok(HttpResponse::InternalServerError()
			.content_type("text/html")
			.body(page));
	};
	let Some(client_id) = client_id else {
		let page = templates::error_page(
			&tera,
			language,
			translations,
			templates::ErrorPage::ClientNotFound,
		)
		.unwrap_or_else(|_| String::from(REALLY_BAD_ERROR_PAGE));
		return Ok(HttpResponse::NotFound()
			.content_type("text/html")
			.body(page));
	};

	// verify redirect uri
	let redirect_uri = match get_redirect_uri(&params.redirect_uri, db, client_id).await {
		Ok(uri) => uri,
		Err(e) => {
			let e = e
				.expected()
				.unwrap_or(templates::ErrorPage::InternalServerError);
			let page = error_page(&tera, &translations, e)
				.unwrap_or_else(|_| String::from(REALLY_BAD_ERROR_PAGE));
			return Ok(HttpResponse::BadRequest()
				.content_type("text/html")
				.body(page));
		}
	};

	let state = &params.state;
	let internal_server_error =
		AuthorizeError::internal_server_error(redirect_uri.clone(), state.clone());

	// verify scope
	let _ = match get_scope(&params.scope, db, client_id, &redirect_uri, &params.state).await {
		Ok(scope) => scope,
		Err(e) => {
			let e = e.expected().unwrap_or(internal_server_error);
			return Err(e);
		}
	};

	// verify response type
	if params.response_type == ResponseType::Unsupported {
		return Err(AuthorizeError::unsupported_response_type(
			redirect_uri,
			params.state,
		));
	}

	// TODO find a better way of doing languages
	let language = Language::from_str("en").unwrap();
	let page = templates::login_page(&tera, &params, language, translations).unwrap();
	Ok(HttpResponse::Ok().content_type("text/html").body(page))
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

	fn too_many_requests() -> Self {
		Self {
			status_code: StatusCode::UNAUTHORIZED,
			error: TokenErrorType::InvalidClient,
			error_description: Box::from("Too many failed attempts. Please wait one hour."),
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

	fn mismatch_client_id() -> Self {
		Self {
			status_code: StatusCode::UNAUTHORIZED,
			error: TokenErrorType::InvalidClient,
			error_description: Box::from("The client ID in the Authorization header is not the same as the client ID in the request body"),
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
			error_description: format!("Only a confidential client may be used with this flow. The {alias} client is a public client.")
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

	fn untrusted_client() -> Self {
		Self {
			status_code: StatusCode::UNAUTHORIZED,
			error: TokenErrorType::InvalidClient,
			error_description: "Only trusted clients may use this grant".into(),
		}
	}

	fn incorrect_user_credentials() -> Self {
		Self {
			status_code: StatusCode::BAD_REQUEST,
			error: TokenErrorType::InvalidRequest,
			error_description: "The given credentials are incorrect".into(),
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
	http_req: HttpRequest,
	authorization: Option<web::Header<authorization::BasicAuthorization>>,
) -> HttpResponse {
	let db = db.get_ref();
	let request = serde_urlencoded::from_bytes::<TokenRequest>(&req);
	let Ok(request) = request else {
		return TokenError::invalid_request().error_response();
	};
	let config = config::get_config().unwrap();
	let ip = http_req.peer_addr().unwrap().ip();

	let self_id = config.url;
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
				match jwt::verify_auth_code(db, &code, &self_id, client_id, redirect_uri).await {
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

				// brute force detection
				if brute_force_detection::brute_force_detected(db, &client_id.to_string(), ip)
					.await
					.unwrap()
				{
					return TokenError::too_many_requests().error_response();
				}

				if authorization.username() != client_alias.deref() {
					return TokenError::mismatch_client_id().error_response();
				}
				if !hash.check_password(authorization.password()).unwrap() {
					db::add_failed_login_attempt(db, &client_id.to_string(), ip)
						.await
						.unwrap();
					return TokenError::incorrect_client_secret().error_response();
				}
			} else if authorization.is_some() {
				return TokenError::incorrect_client_secret().error_response();
			}

			let access_token = jwt::Claims::access_token(
				db,
				Some(claims.id()),
				self_id,
				client_id,
				claims.subject(),
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
		} => {
			let Some(authorization) = authorization else {
				return TokenError::no_authorization().error_response();
			};
			let client_alias = authorization.username();
			let Some(client_id) = db::get_client_id_by_alias(db, client_alias).await.unwrap() else {
				return TokenError::client_not_found(client_alias).error_response();
			};

			let trusted = db::is_client_trusted(db, client_id).await.unwrap().unwrap();
			if !trusted {
				return TokenError::untrusted_client().error_response();
			}

			// brute force detection
			if brute_force_detection::brute_force_detected(db, &client_id.to_string(), ip)
				.await
				.unwrap()
			{
				return TokenError::too_many_requests().error_response();
			}

			// verify client
			let hash = db::get_client_secret(db, client_id).await.unwrap().unwrap();
			if !hash.check_password(authorization.password()).unwrap() {
				db::add_failed_login_attempt(db, &client_id.to_string(), ip)
					.await
					.unwrap();
				return TokenError::incorrect_client_secret().error_response();
			}

			// brute force detection
			if brute_force_detection::brute_force_detected(db, &username, ip)
				.await
				.unwrap()
			{
				return TokenError::too_many_requests().error_response();
			}

			// authenticate user
			let Some(user_id) = authenticate_user(db, &username, &password).await.unwrap() else {
				db::add_failed_login_attempt(db, &username, ip).await.unwrap();
				return TokenError::incorrect_user_credentials().error_response();
			};

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
				jwt::Claims::access_token(db, None, self_id, client_id, user_id, duration, &scope)
					.await
					.unwrap();
			let refresh_token = jwt::Claims::refresh_token(db, &access_token).await.unwrap();

			let expires_in = access_token.expires_in();
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

			// brute force detection
			if brute_force_detection::brute_force_detected(db, &client_id.to_string(), ip)
				.await
				.unwrap()
			{
				return TokenError::too_many_requests().error_response();
			}

			// verify client
			let hash = db::get_client_secret(db, client_id).await.unwrap().unwrap();
			if !hash.check_password(authorization.password()).unwrap() {
				db::add_failed_login_attempt(db, &client_id.to_string(), ip)
					.await
					.unwrap();
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

			let access_token = jwt::Claims::access_token(
				db, None, self_id, client_id, client_id, duration, &scope,
			)
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
			let claims = match jwt::verify_refresh_token(db, &refresh_token, &self_id).await {
				Ok(claims) => claims,
				Err(e) => {
					let e = e.unwrap();
					return TokenError::bad_refresh_token(e).error_response();
				}
			};

			let client_id = claims.client_id();
			if let Some(authorization) = authorization {
				let client_alias = authorization.username();
				let Some(id) = db::get_client_id_by_alias(db, client_alias).await.unwrap() else {
					return TokenError::client_not_found(client_alias).error_response();
				};

				// brute force detection
				if brute_force_detection::brute_force_detected(db, &client_id.to_string(), ip)
					.await
					.unwrap()
				{
					return TokenError::too_many_requests().error_response();
				}

				// authenticate client
				if let Some(hash) = db::get_client_secret(db, id).await.unwrap() {
					if !hash.check_password(authorization.password()).unwrap() {
						db::add_failed_login_attempt(db, &client_id.to_string(), ip)
							.await
							.unwrap();
						return TokenError::incorrect_client_secret().error_response();
					}
				} else {
					return TokenError::incorrect_client_secret().error_response();
				}
			} else if db::get_client_secret(db, client_id)
				.await
				.unwrap()
				.is_some()
			{
				return TokenError::no_authorization().error_response();
			}

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

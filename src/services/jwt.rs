use chrono::{serde::ts_milliseconds, serde::ts_milliseconds_option, DateTime, Duration, Utc};
use exun::{Expect, RawUnexpected, ResultErrorExt};
use jwt::{SignWithKey, VerifyWithKey};
use raise::yeet;
use serde::{Deserialize, Serialize};
use sqlx::{Executor, MySql, MySqlPool};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use super::{db, id::new_id, secrets};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenType {
	Authorization,
	Access,
	Refresh,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
	iss: Url,
	sub: Uuid,
	aud: Box<[String]>,
	#[serde(with = "ts_milliseconds")]
	exp: DateTime<Utc>,
	#[serde(with = "ts_milliseconds_option")]
	nbf: Option<DateTime<Utc>>,
	#[serde(with = "ts_milliseconds")]
	iat: DateTime<Utc>,
	jti: Uuid,
	scope: Box<str>,
	client_id: Uuid,
	token_type: TokenType,
	auth_code_id: Option<Uuid>,
	redirect_uri: Option<Url>,
}

#[derive(Debug, Clone, Copy, sqlx::Type)]
#[sqlx(rename_all = "kebab-case")]
pub enum RevokedRefreshTokenReason {
	ReusedAuthorizationCode,
	NewRefreshToken,
}

impl Claims {
	pub async fn auth_code<'c>(
		db: &MySqlPool,
		self_id: Url,
		client_id: Uuid,
		sub: Uuid,
		scopes: &str,
		redirect_uri: &Url,
	) -> Result<Self, RawUnexpected> {
		let five_minutes = Duration::minutes(5);

		let id = new_id(db, db::auth_code_exists).await?;
		let iat = Utc::now();
		let exp = iat + five_minutes;

		db::create_auth_code(db, id, exp).await?;

		let aud = [self_id.to_string(), client_id.to_string()].into();

		Ok(Self {
			iss: self_id,
			sub,
			aud,
			exp,
			nbf: None,
			iat,
			jti: id,
			scope: scopes.into(),
			client_id,
			auth_code_id: Some(id),
			token_type: TokenType::Authorization,
			redirect_uri: Some(redirect_uri.clone()),
		})
	}

	pub async fn access_token<'c>(
		db: &MySqlPool,
		auth_code_id: Option<Uuid>,
		self_id: Url,
		client_id: Uuid,
		sub: Uuid,
		duration: Duration,
		scopes: &str,
	) -> Result<Self, RawUnexpected> {
		let id = new_id(db, db::access_token_exists).await?;
		let iat = Utc::now();
		let exp = iat + duration;

		db::create_access_token(db, id, auth_code_id, exp)
			.await
			.unexpect()?;

		let aud = [self_id.to_string(), client_id.to_string()].into();

		Ok(Self {
			iss: self_id,
			sub,
			aud,
			exp,
			nbf: None,
			iat,
			jti: id,
			scope: scopes.into(),
			client_id,
			auth_code_id,
			token_type: TokenType::Access,
			redirect_uri: None,
		})
	}

	pub async fn refresh_token(
		db: &MySqlPool,
		other_token: &Claims,
	) -> Result<Self, RawUnexpected> {
		let one_day = Duration::days(1);

		let id = new_id(db, db::refresh_token_exists).await?;
		let iat = Utc::now();
		let exp = other_token.exp + one_day;

		db::create_refresh_token(db, id, other_token.auth_code_id, exp).await?;

		let mut claims = other_token.clone();
		claims.exp = exp;
		claims.iat = iat;
		claims.jti = id;
		claims.token_type = TokenType::Refresh;

		Ok(claims)
	}

	pub async fn refreshed_access_token(
		db: &MySqlPool,
		refresh_token: &Claims,
		exp_time: Duration,
	) -> Result<Self, RawUnexpected> {
		let id = new_id(db, db::access_token_exists).await?;
		let iat = Utc::now();
		let exp = iat + exp_time;

		db::create_access_token(db, id, refresh_token.auth_code_id, exp).await?;

		let mut claims = refresh_token.clone();
		claims.exp = exp;
		claims.iat = iat;
		claims.jti = id;
		claims.token_type = TokenType::Access;

		Ok(claims)
	}

	pub fn id(&self) -> Uuid {
		self.jti
	}

	pub fn subject(&self) -> Uuid {
		self.sub
	}

	pub fn expires_in(&self) -> i64 {
		(self.exp - Utc::now()).num_seconds()
	}

	pub fn scopes(&self) -> &str {
		&self.scope
	}

	pub fn client_id(&self) -> Uuid {
		self.client_id
	}

	pub fn to_jwt(&self) -> Result<Box<str>, RawUnexpected> {
		let key = secrets::signing_key()?;
		let jwt = self.sign_with_key(&key)?.into_boxed_str();
		Ok(jwt)
	}
}

#[derive(Debug, Error)]
pub enum VerifyJwtError {
	#[error("{0}")]
	ParseJwtError(#[from] jwt::Error),
	#[error("The issuer for this token is incorrect")]
	IncorrectIssuer,
	#[error("This bearer token was intended for a different client")]
	WrongClient,
	#[error("The given audience parameter does not contain this issuer")]
	BadAudience,
	#[error("The redirect URI doesn't match what's in the token")]
	IncorrectRedirectUri,
	#[error("The token is expired")]
	ExpiredToken,
	#[error("The token cannot be used yet")]
	NotYet,
	#[error("The bearer token has been revoked")]
	JwtRevoked,
}

fn verify_jwt(
	token: &str,
	self_id: &Url,
	client_id: Option<Uuid>,
) -> Result<Claims, Expect<VerifyJwtError>> {
	let key = secrets::signing_key()?;
	let claims: Claims = token
		.verify_with_key(&key)
		.map_err(|e| VerifyJwtError::from(e))?;

	if &claims.iss != self_id {
		yeet!(VerifyJwtError::IncorrectIssuer.into())
	}

	if let Some(client_id) = client_id {
		if claims.client_id != client_id {
			yeet!(VerifyJwtError::WrongClient.into())
		}
	}

	if !claims.aud.contains(&self_id.to_string()) {
		yeet!(VerifyJwtError::BadAudience.into())
	}

	let now = Utc::now();

	if now > claims.exp {
		yeet!(VerifyJwtError::ExpiredToken.into())
	}

	if let Some(nbf) = claims.nbf {
		if now < nbf {
			yeet!(VerifyJwtError::NotYet.into())
		}
	}

	Ok(claims)
}

pub async fn verify_auth_code<'c>(
	db: &MySqlPool,
	token: &str,
	self_id: &Url,
	client_id: Uuid,
	redirect_uri: Url,
) -> Result<Claims, Expect<VerifyJwtError>> {
	let claims = verify_jwt(token, self_id, Some(client_id))?;

	if let Some(claimed_uri) = &claims.redirect_uri {
		if claimed_uri.clone() != redirect_uri {
			yeet!(VerifyJwtError::IncorrectRedirectUri.into());
		}
	}

	if db::delete_auth_code(db, claims.jti).await? {
		db::delete_access_tokens_with_auth_code(db, claims.jti).await?;
		db::revoke_refresh_tokens_with_auth_code(db, claims.jti).await?;
		yeet!(VerifyJwtError::JwtRevoked.into());
	}

	Ok(claims)
}

pub async fn verify_access_token<'c>(
	db: impl Executor<'c, Database = MySql>,
	token: &str,
	self_id: &Url,
	client_id: Uuid,
) -> Result<Claims, Expect<VerifyJwtError>> {
	let claims = verify_jwt(token, self_id, Some(client_id))?;

	if !db::access_token_exists(db, claims.jti).await? {
		yeet!(VerifyJwtError::JwtRevoked.into())
	}

	Ok(claims)
}

pub async fn verify_refresh_token<'c>(
	db: impl Executor<'c, Database = MySql> + Clone,
	token: &str,
	self_id: &Url,
) -> Result<Claims, Expect<VerifyJwtError>> {
	let claims = verify_jwt(token, self_id, None)?;

	if db::refresh_token_revoked(db.clone(), claims.jti).await? {
		yeet!(VerifyJwtError::JwtRevoked.into())
	}

	db::revoke_refresh_token(db, claims.jti).await?;

	Ok(claims)
}

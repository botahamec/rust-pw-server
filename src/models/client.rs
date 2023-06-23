use std::{hash::Hash, marker::PhantomData};

use actix_web::{http::StatusCode, ResponseError};
use exun::{Expect, RawUnexpected};
use raise::yeet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::services::crypto::PasswordHash;

/// There are two types of clients, based on their ability to maintain the
/// security of their client credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClientType {
	/// A client that is capable of maintaining the confidentiality of their
	/// credentials, or capable of secure client authentication using other
	/// means. An example would be a secure server with restricted access to
	/// the client credentials.
	Confidential,
	/// A client that is incapable of maintaining the confidentiality of their
	/// credentials and cannot authenticate securely by any other means, such
	/// as an installed application, or a web-browser based application.
	Public,
}

#[derive(Debug, Clone)]
pub struct Client {
	id: Uuid,
	ty: ClientType,
	alias: Box<str>,
	secret: Option<PasswordHash>,
	allowed_scopes: Box<[Box<str>]>,
	default_scopes: Option<Box<[Box<str>]>>,
	redirect_uris: Box<[Url]>,
	trusted: bool,
}

impl PartialEq for Client {
	fn eq(&self, other: &Self) -> bool {
		self.id == other.id
	}
}

impl Eq for Client {}

impl Hash for Client {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		state.write_u128(self.id.as_u128())
	}
}

#[derive(Debug, Clone, Copy, Error)]
#[error("Confidential clients must have a secret, but it was not provided")]
pub enum CreateClientError {
	#[error("Confidential clients must have a secret, but it was not provided")]
	NoSecret,
	#[error("Only confidential clients may be trusted")]
	TrustedError,
}

impl ResponseError for CreateClientError {
	fn status_code(&self) -> StatusCode {
		StatusCode::BAD_REQUEST
	}
}

impl Client {
	pub fn new(
		id: Uuid,
		alias: &str,
		ty: ClientType,
		secret: Option<&str>,
		allowed_scopes: Box<[Box<str>]>,
		default_scopes: Option<Box<[Box<str>]>>,
		redirect_uris: &[Url],
		trusted: bool,
	) -> Result<Self, Expect<CreateClientError>> {
		let secret = if let Some(secret) = secret {
			Some(PasswordHash::new(secret)?)
		} else {
			None
		};

		if ty == ClientType::Confidential && secret.is_none() {
			yeet!(CreateClientError::NoSecret.into());
		}

		if ty == ClientType::Public && trusted {
			yeet!(CreateClientError::TrustedError.into());
		}

		Ok(Self {
			id,
			alias: Box::from(alias),
			ty,
			secret,
			allowed_scopes,
			default_scopes,
			redirect_uris: redirect_uris.into_iter().cloned().collect(),
			trusted,
		})
	}

	pub fn id(&self) -> Uuid {
		self.id
	}

	pub fn alias(&self) -> &str {
		&self.alias
	}

	pub fn client_type(&self) -> ClientType {
		self.ty
	}

	pub fn redirect_uris(&self) -> &[Url] {
		&self.redirect_uris
	}

	pub fn secret_hash(&self) -> Option<&[u8]> {
		self.secret.as_ref().map(|s| s.hash())
	}

	pub fn secret_salt(&self) -> Option<&[u8]> {
		self.secret.as_ref().map(|s| s.salt())
	}

	pub fn secret_version(&self) -> Option<u8> {
		self.secret.as_ref().map(|s| s.version())
	}

	pub fn allowed_scopes(&self) -> String {
		self.allowed_scopes.join(" ")
	}

	pub fn default_scopes(&self) -> Option<String> {
		self.default_scopes.clone().map(|s| s.join(" "))
	}

	pub fn is_trusted(&self) -> bool {
		self.trusted
	}

	pub fn check_secret(&self, secret: &str) -> Option<Result<bool, RawUnexpected>> {
		self.secret.as_ref().map(|s| s.check_password(secret))
	}
}

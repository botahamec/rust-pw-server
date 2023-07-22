use std::{fmt::Display, hash::Hash, str::FromStr};

use actix_web::{http::StatusCode, ResponseError};
use exun::{Expect, RawUnexpected};
use raise::yeet;
use serde::{Deserialize, Serialize};
use sqlx::{mysql::MySqlTypeInfo, MySql};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::services::crypto::PasswordHash;

/// There are two types of clients, based on their ability to maintain the
/// security of their client credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

impl Display for ClientType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			Self::Confidential => "confidential",
			Self::Public => "public",
		})
	}
}

impl FromStr for ClientType {
	type Err = ();

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"confidential" => Ok(Self::Confidential),
			"public" => Ok(Self::Public),
			_ => Err(()),
		}
	}
}

impl sqlx::Type<MySql> for ClientType {
	fn type_info() -> MySqlTypeInfo {
		<str as sqlx::Type<MySql>>::type_info()
	}
}

impl sqlx::Encode<'_, MySql> for ClientType {
	fn encode_by_ref(
		&self,
		buf: &mut <MySql as sqlx::database::HasArguments<'_>>::ArgumentBuffer,
	) -> sqlx::encode::IsNull {
		<String as sqlx::Encode<MySql>>::encode_by_ref(&self.to_string(), buf)
	}
}

impl sqlx::Decode<'_, MySql> for ClientType {
	fn decode(
		value: <MySql as sqlx::database::HasValueRef<'_>>::ValueRef,
	) -> Result<Self, sqlx::error::BoxDynError> {
		<&str as sqlx::Decode<MySql>>::decode(value).map(|s| s.parse().unwrap())
	}
}

impl From<String> for ClientType {
	fn from(value: String) -> Self {
		// TODO banish this abomination back to the shadows from whence it came
		value.parse().unwrap()
	}
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
	#[error("Trusted clients must be confidential")]
	TrustedError,
	#[error("Redirect URIs must not include a fragment component")]
	UriFragment,
	#[error("Redirect URIs must use HTTPS")]
	NonHttpsUri,
	#[error("The default scope is not a subset of the allowed scopes for this client")]
	ImpermissibleDefaultScopes,
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

		if let Some(default_scopes) = &default_scopes {
			let default_scopes = default_scopes.join(" ");
			let allowed_scopes = allowed_scopes.join(" ");
			if !crate::scopes::is_subset_of(&default_scopes, &allowed_scopes) {
				yeet!(CreateClientError::ImpermissibleDefaultScopes.into());
			}
		}

		for redirect_uri in redirect_uris {
			if redirect_uri.scheme() != "https" {
				yeet!(CreateClientError::NonHttpsUri.into())
			}

			if redirect_uri.fragment().is_some() {
				yeet!(CreateClientError::UriFragment.into())
			}
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

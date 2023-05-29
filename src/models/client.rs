use std::{hash::Hash, marker::PhantomData};

use exun::{Expect, RawUnexpected};
use raise::yeet;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::services::crypto::PasswordHash;

/// There are two types of clients, based on their ability to maintain the
/// security of their client credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
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
	ty: ClientType,
	id: Uuid,
	secret: Option<PasswordHash>,
	redirect_uris: Box<[Url]>,
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
pub struct NoSecretError {
	_phantom: PhantomData<()>,
}

impl NoSecretError {
	fn new() -> Self {
		Self {
			_phantom: PhantomData,
		}
	}
}

impl Client {
	pub fn new_public(
		id: Uuid,
		ty: ClientType,
		secret: Option<&str>,
		redirect_uris: &[Url],
	) -> Result<Self, Expect<NoSecretError>> {
		let secret = if let Some(secret) = secret {
			Some(PasswordHash::new(secret)?)
		} else {
			None
		};

		if ty == ClientType::Confidential && secret.is_none() {
			yeet!(NoSecretError::new().into());
		}

		Ok(Self {
			id,
			ty: ClientType::Public,
			secret,
			redirect_uris: redirect_uris.into_iter().cloned().collect(),
		})
	}

	pub fn id(&self) -> Uuid {
		self.id
	}

	pub fn client_type(&self) -> ClientType {
		self.ty
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

	pub fn check_secret(&self, secret: &str) -> Option<Result<bool, RawUnexpected>> {
		self.secret.as_ref().map(|s| s.check_password(secret))
	}
}

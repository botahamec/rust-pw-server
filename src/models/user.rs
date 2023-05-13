use std::hash::Hash;

use exun::RawUnexpected;
use uuid::Uuid;

use crate::services::crypto::PasswordHash;

#[derive(Debug, Clone)]
pub struct User {
	pub user_id: Uuid,
	pub username: Box<str>,
	pub password: PasswordHash,
}

impl PartialEq for User {
	fn eq(&self, other: &Self) -> bool {
		self.user_id == other.user_id
	}
}

impl Eq for User {}

impl Hash for User {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		state.write_u128(self.user_id.as_u128())
	}
}

impl User {
	pub fn username(&self) -> &str {
		&self.username
	}

	pub fn password_hash(&self) -> &[u8] {
		self.password.hash()
	}

	pub fn password_salt(&self) -> &[u8] {
		self.password.salt()
	}

	pub fn password_version(&self) -> u8 {
		self.password.version()
	}

	pub fn check_password(&self, password: &str) -> Result<bool, RawUnexpected> {
		self.password.check_password(password)
	}
}

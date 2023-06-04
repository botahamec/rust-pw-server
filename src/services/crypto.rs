use std::hash::Hash;

use argon2::{hash_raw, verify_raw};
use exun::RawUnexpected;

use crate::services::secrets::pepper;

/// The configuration used for hashing and verifying passwords
///
/// # Example
///
/// ```
/// use crate::services::secrets;
///
/// let pepper = secrets::pepper();
/// let config = config(&pepper);
/// ```
fn config<'a>(pepper: &'a [u8]) -> argon2::Config<'a> {
	argon2::Config {
		hash_length: 32,
		lanes: 4,
		mem_cost: 5333,
		time_cost: 4,
		secret: pepper,

		ad: &[],
		thread_mode: argon2::ThreadMode::Sequential,
		variant: argon2::Variant::Argon2i,
		version: argon2::Version::Version13,
	}
}

/// A password hash and salt for a user
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordHash {
	hash: Box<[u8]>,
	salt: Box<[u8]>,
	version: u8,
}

impl Hash for PasswordHash {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		state.write(&self.hash)
	}
}

impl PasswordHash {
	/// Hash a password using Argon2
	pub fn new(password: &str) -> Result<Self, RawUnexpected> {
		let password = password.as_bytes();

		let salt: [u8; 32] = rand::random();
		let salt = Box::from(salt);
		let pepper = pepper()?;
		let hash = hash_raw(password, &salt, &config(&pepper))?.into_boxed_slice();

		Ok(Self {
			hash,
			salt,
			version: 0,
		})
	}

	/// Create this structure from a given hash and salt
	pub fn from_fields(hash: &[u8], salt: &[u8], version: u8) -> Self {
		Self {
			hash: Box::from(hash),
			salt: Box::from(salt),
			version,
		}
	}

	/// Get the password hash
	pub fn hash(&self) -> &[u8] {
		&self.hash
	}

	/// Get the salt used for the hash
	pub fn salt(&self) -> &[u8] {
		&self.salt
	}

	pub fn version(&self) -> u8 {
		self.version
	}

	/// Check if the given password is the one that was hashed
	pub fn check_password(&self, password: &str) -> Result<bool, RawUnexpected> {
		let pepper = pepper()?;
		Ok(verify_raw(
			password.as_bytes(),
			&self.salt,
			&self.hash,
			&config(&pepper),
		)?)
	}
}

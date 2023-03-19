use std::hash::Hash;

use argon2::{hash_raw, verify_raw};
use exun::RawUnexpected;

/// A custom pepper used to hide passwords
static PEPPER: [u8; 16] = [
	0x98, 0x7f, 0x6f, 0xce, 0x20, 0x76, 0x2c, 0x8a, 0xae, 0xf6, 0xee, 0x45, 0xb3, 0x6b, 0x1f, 0x69,
];

/// The configuration used for hashing and verifying passwords
static CONFIG: argon2::Config<'_> = argon2::Config {
	hash_length: 256,
	lanes: 4,
	mem_cost: 5333,
	time_cost: 4,
	secret: &PEPPER,

	ad: &[],
	thread_mode: argon2::ThreadMode::Sequential,
	variant: argon2::Variant::Argon2i,
	version: argon2::Version::Version13,
};

/// A password hash and salt for a user
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordHash {
	hash: Box<[u8]>,
	salt: Box<[u8]>,
}

impl Hash for PasswordHash {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		for byte in self.hash.iter() {
			state.write_u8(*byte)
		}
	}
}

impl PasswordHash {
	/// Hash a password using Argon2
	pub fn new(password: &str) -> Result<Self, RawUnexpected> {
		let password = password.as_bytes();

		let salt: [u8; 16] = rand::random();
		let salt = Box::from(salt);

		let hash = hash_raw(password, &salt, &CONFIG)?.into_boxed_slice();

		Ok(Self { hash, salt })
	}

	/// Create this structure from a given hash and salt
	pub fn from_hash_salt(hash: &[u8], salt: &[u8]) -> Self {
		Self {
			hash: Box::from(hash),
			salt: Box::from(salt),
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

	/// Check if the given password is the one that was hashed
	pub fn check_password(&self, password: &str) -> Result<bool, RawUnexpected> {
		Ok(verify_raw(
			password.as_bytes(),
			&self.salt,
			&self.hash,
			&CONFIG,
		)?)
	}
}

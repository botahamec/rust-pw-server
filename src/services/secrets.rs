use std::env;

use exun::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// This is a secret salt, needed for creating passwords. It's used as an extra
/// layer of security, on top of the salt that's already used.
pub fn pepper() -> Result<Box<[u8]>, RawUnexpected> {
	let pepper = env::var("SECRET_SALT")?;
	let pepper = hex::decode(pepper)?;
	Ok(pepper.into_boxed_slice())
}

/// The URL to the MySQL database
pub fn database_url() -> Result<String, RawUnexpected> {
	env::var("DATABASE_URL").unexpect()
}

pub fn signing_key() -> Result<Hmac<Sha256>, RawUnexpected> {
	let key = env::var("PRIVATE_KEY")?;
	let key = Hmac::<Sha256>::new_from_slice(key.as_bytes())?;
	Ok(key)
}

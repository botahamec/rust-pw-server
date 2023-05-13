use std::env;

use exun::*;

pub fn pepper() -> Result<Box<[u8]>, RawUnexpected> {
	let pepper = env::var("SECRET_SALT")?;
	let pepper = hex::decode(pepper)?;
	Ok(pepper.into_boxed_slice())
}

pub fn database_url() -> Result<String, RawUnexpected> {
	env::var("DATABASE_URL").unexpect()
}

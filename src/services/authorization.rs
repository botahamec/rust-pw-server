use base64::Engine;
use raise::yeet;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum ParseBasicError {
	#[error("Basic Authorization is required")]
	NotBasic,
	#[error("No credentials were provided for authorization")]
	NoCredentials,
	#[error("The credentials provided were not base64")]
	InvalidBase64,
	#[error("The decoded base64 credentials were not UTF-8")]
	NotUtf8,
	#[error("A colon (:) must be used to delimit the username and password")]
	NoColon,
}

/// Returns a username and a password from a Basic authorization header
pub fn parse_basic(value: &str) -> Result<(Box<str>, Box<str>), ParseBasicError> {
	if !value.starts_with("Basic") {
		yeet!(ParseBasicError::NotBasic);
	}

	let value: String = value
		.chars()
		.skip(5)
		.skip_while(|ch| ch.is_whitespace())
		.collect();

	if value.is_empty() {
		yeet!(ParseBasicError::NoCredentials);
	}

	let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(value) else {
		yeet!(ParseBasicError::InvalidBase64)
	};

	let Ok(value) = String::from_utf8(bytes) else {
		yeet!(ParseBasicError::NotUtf8)
	};

	let mut parts = value.split(':');
	let username = parts.next().unwrap();
	let Some(password) = parts.next() else {
		yeet!(ParseBasicError::NoColon)
	};

	Ok((Box::from(username), Box::from(password)))
}

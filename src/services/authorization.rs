use actix_web::{
	error::ParseError,
	http::header::{self, Header, HeaderName, HeaderValue, InvalidHeaderValue, TryIntoHeaderValue},
};
use base64::Engine;
use raise::yeet;

#[derive(Clone)]
pub struct BasicAuthorization {
	username: Box<str>,
	password: Box<str>,
}

impl TryIntoHeaderValue for BasicAuthorization {
	type Error = InvalidHeaderValue;

	fn try_into_value(self) -> Result<HeaderValue, Self::Error> {
		let username = self.username;
		let password = self.password;
		let utf8 = format!("{username}:{password}");
		let b64 = base64::engine::general_purpose::STANDARD.encode(utf8);
		let value = format!("Basic {b64}");
		HeaderValue::from_str(&value)
	}
}

impl Header for BasicAuthorization {
	fn name() -> HeaderName {
		header::AUTHORIZATION
	}

	fn parse<M: actix_web::HttpMessage>(msg: &M) -> Result<Self, actix_web::error::ParseError> {
		let Some(value) = msg.headers().get(Self::name()) else {
			yeet!(ParseError::Header)
		};

		let Ok(value) = value.to_str() else {
			yeet!(ParseError::Header)
		};

		if !value.starts_with("Basic") {
			yeet!(ParseError::Header);
		}

		let value: String = value
			.chars()
			.skip(5)
			.skip_while(|ch| ch.is_whitespace())
			.collect();

		if value.is_empty() {
			yeet!(ParseError::Header);
		}

		let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(value) else {
			yeet!(ParseError::Header)
		};

		let Ok(value) = String::from_utf8(bytes) else {
			yeet!(ParseError::Header)
		};

		let mut parts = value.split(':');
		let username = Box::from(parts.next().unwrap());
		let Some(password) = parts.next() else {
			yeet!(ParseError::Header)
		};
		let password = Box::from(password);

		Ok(Self { username, password })
	}
}

impl BasicAuthorization {
	pub fn username(&self) -> &str {
		&self.username
	}

	pub fn password(&self) -> &str {
		&self.password
	}
}

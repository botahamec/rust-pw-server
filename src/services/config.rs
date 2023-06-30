use std::{
	fmt::{self, Display},
	str::FromStr,
};

use exun::RawUnexpected;
use parking_lot::RwLock;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

static ENVIRONMENT: RwLock<Environment> = RwLock::new(Environment::Local);

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
	pub id: Box<str>,
	pub url: Url,
}

pub fn get_config() -> Result<Config, RawUnexpected> {
	let env = get_environment();
	let path = format!("static/config/{env}.toml");
	let string = std::fs::read_to_string(path)?;
	let config = toml::from_str(&string)?;
	Ok(config)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Environment {
	Local,
	Dev,
	Staging,
	Production,
}

impl Display for Environment {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Local => f.write_str("local"),
			Self::Dev => f.write_str("dev"),
			Self::Staging => f.write_str("staging"),
			Self::Production => f.write_str("prod"),
		}
	}
}

#[derive(Debug, Clone, Error)]
#[error("Expected one of the following environments: local, dev, staging, prod. Found {string}")]
pub struct ParseEnvironmentError {
	string: Box<str>,
}

impl FromStr for Environment {
	type Err = ParseEnvironmentError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"local" => Ok(Self::Local),
			"dev" => Ok(Self::Dev),
			"staging" => Ok(Self::Staging),
			"prod" => Ok(Self::Production),
			_ => Err(ParseEnvironmentError { string: s.into() }),
		}
	}
}

pub fn set_environment(env: Environment) {
	let mut env_ptr = ENVIRONMENT.write();
	*env_ptr = env;
}

fn get_environment() -> Environment {
	ENVIRONMENT.read().clone()
}

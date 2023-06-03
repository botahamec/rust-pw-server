use std::fmt::{self, Display};

use crate::models::{client::Client, user::User};

use super::{Action, Scope};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Admin;

impl Display for Admin {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("admin")
	}
}

impl Scope for Admin {
	fn parse_modifiers(_modifiers: &str) -> Result<Self, Box<str>> {
		Ok(Self)
	}

	fn has_user_permission(&self, _: &User, _: &Action<User>) -> bool {
		true
	}

	fn has_client_permission(&self, _: &User, _: &Action<Client>) -> bool {
		true
	}
}

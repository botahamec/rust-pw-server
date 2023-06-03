use std::collections::HashSet;

use self::admin::Admin;
use crate::models::{client::Client, user::User};

mod admin;

/// The action which was attempted on a resource
pub enum Action<T> {
	Create(T),
	Read(T),
	Update(T, T),
	Delete(T),
}

trait ScopeSuperSet {
	fn is_superset_of(&self, other: &Self) -> bool;
}

trait Scope: ToString {
	/// Parse a scope of the format: `{Scope::NAME}:{modifiers}`
	fn parse_modifiers(modifiers: &str) -> Result<Self, Box<str>>
	where
		Self: Sized;

	/// Returns `true` if and only if the given `user` is allowed to take the
	/// given `action` with this scope
	fn has_user_permission(&self, user: &User, action: &Action<User>) -> bool;

	// Returns `true` if and only if the given `user` is allowed to take the
	/// given `action` with this scope
	fn has_client_permission(&self, user: &User, action: &Action<Client>) -> bool;
}

pub struct ParseScopeError {
	scope: Box<str>,
	error: ParseScopeErrorType,
}

impl ParseScopeError {
	fn invalid_type(scope: &str, scope_type: &str) -> Self {
		let scope = scope.into();
		let error = ParseScopeErrorType::InvalidType(scope_type.into());
		Self { scope, error }
	}
}

pub enum ParseScopeErrorType {
	InvalidType(Box<str>),
	InvalidModifiers(Box<str>),
}

fn parse_scope(scope: &str) -> Result<Box<dyn Scope>, ParseScopeError> {
	let mut split = scope.split(':');
	let scope_type = split.next().unwrap();
	let _modifiers: String = split.collect();

	match scope_type {
		"admin" => Ok(Box::new(Admin)),
		_ => Err(ParseScopeError::invalid_type(scope, scope_type)),
	}
}

fn parse_scopes(scopes: &str) -> Result<Vec<Box<dyn Scope>>, ParseScopeError> {
	scopes
		.split_whitespace()
		.map(|scope| parse_scope(scope))
		.collect()
}

fn parse_scopes_errors(
	results: &[Result<Box<dyn Scope>, ParseScopeError>],
) -> Vec<&ParseScopeError> {
	let mut errors = Vec::with_capacity(results.len());
	for result in results {
		if let Err(pse) = result {
			errors.push(pse)
		}
	}

	errors
}

/// Returns `true` if and only if all values in `left_scopes` are contained in
/// `right_scopes`.
pub fn is_subset_of(left_scopes: &str, right_scopes: &str) -> bool {
	let right_scopes: HashSet<&str> = right_scopes.split_whitespace().collect();

	for scope in left_scopes.split_whitespace() {
		if !right_scopes.contains(scope) {
			return false;
		}
	}

	true
}

pub fn has_user_permission(
	user: User,
	action: Action<User>,
	client_scopes: &str,
) -> Result<bool, ParseScopeError> {
	let scopes = parse_scopes(client_scopes)?;

	for scope in scopes {
		if scope.has_user_permission(&user, &action) {
			return Ok(true);
		}
	}

	Ok(false)
}

pub fn has_client_permission(
	user: User,
	action: Action<Client>,
	client_scopes: &str,
) -> Result<bool, ParseScopeError> {
	let scopes = parse_scopes(client_scopes)?;

	for scope in scopes {
		if scope.has_client_permission(&user, &action) {
			return Ok(true);
		}
	}

	Ok(false)
}

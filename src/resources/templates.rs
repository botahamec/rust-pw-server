use std::collections::HashMap;

use exun::{RawUnexpected, ResultErrorExt};
use raise::yeet;
use serde::Serialize;
use tera::{Function, Tera, Value};
use unic_langid::subtags::Language;

use crate::api::AuthorizationParameters;

use super::languages;

fn make_msg(language: Language, translations: languages::Translations) -> impl Function {
	Box::new(
		move |args: &HashMap<String, Value>| -> tera::Result<Value> {
			let Some(key) = args.get("key") else { yeet!("No parameter 'key' provided".into()) };
			let Some(key) = key.as_str() else { yeet!(format!("{} is not a string", key).into()) };
			let Some(value) = translations.get_message(language, key) else { yeet!(format!("{} does not exist", key).into()) };
			Ok(Value::String(value))
		},
	)
}

fn extend_tera(
	tera: &Tera,
	language: Language,
	translations: languages::Translations,
) -> Result<Tera, RawUnexpected> {
	let mut new_tera = initialize()?;
	new_tera.extend(tera)?;
	new_tera.register_function("msg", make_msg(language, translations));
	Ok(new_tera)
}

pub fn initialize() -> tera::Result<Tera> {
	let tera = Tera::new("static/templates/*")?;
	Ok(tera)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorPage {
	InvalidRequest,
	ClientNotFound,
	MissingRedirectUri,
	InvalidRedirectUri,
	InternalServerError,
}

pub fn error_page(
	tera: &Tera,
	language: Language,
	mut translations: languages::Translations,
	error: ErrorPage,
) -> Result<String, RawUnexpected> {
	translations.refresh()?;
	let mut tera = extend_tera(tera, language, translations)?;
	tera.full_reload()?;

	let error = serde_variant::to_variant_name(&error)?;
	let header = format!("errorHeader_{error}");
	let message = format!("errorMessage_{error}");

	let mut context = tera::Context::new();
	context.insert("lang", language.as_str());
	context.insert("errorHeader", &header);
	context.insert("errormessage", &message);

	tera.render("error.html", &context).unexpect()
}

pub fn login_page(
	tera: &Tera,
	params: &AuthorizationParameters,
	language: Language,
	mut translations: languages::Translations,
) -> Result<String, RawUnexpected> {
	translations.refresh()?;
	let mut tera = extend_tera(tera, language, translations)?;
	tera.full_reload()?;
	let mut context = tera::Context::new();
	context.insert("lang", language.as_str());
	context.insert("params", &serde_urlencoded::to_string(params)?);
	tera.render("login.html", &context).unexpect()
}

pub fn login_error_page(
	tera: &Tera,
	params: &AuthorizationParameters,
	language: Language,
	mut translations: languages::Translations,
) -> Result<String, RawUnexpected> {
	translations.refresh()?;
	let mut tera = extend_tera(tera, language, translations)?;
	tera.full_reload()?;
	let mut context = tera::Context::new();
	context.insert("lang", language.as_str());
	context.insert("params", &serde_urlencoded::to_string(params)?);
	context.insert("errorMessage", "loginErrorMessage");
	tera.render("login.html", &context).unexpect()
}

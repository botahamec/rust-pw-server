use std::collections::HashMap;

use exun::{RawUnexpected, ResultErrorExt};
use raise::yeet;
use tera::{Function, Tera, Value};
use unic_langid::subtags::Language;

use super::languages;

fn make_lang(language: Language) -> impl Function {
	Box::new(move |_: &HashMap<String, Value>| -> tera::Result<Value> {
		Ok(Value::String(language.to_string()))
	})
}

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

fn make_base_url() -> impl Function {
	Box::new(|_: &HashMap<String, Value>| Ok(Value::String("foo".to_string())))
}

fn extend_tera(
	tera: &Tera,
	language: Language,
	translations: languages::Translations,
) -> Result<Tera, RawUnexpected> {
	let mut new_tera = initialize()?;
	new_tera.extend(tera)?;
	new_tera.register_function("lang", make_lang(language));
	new_tera.register_function("msg", make_msg(language, translations));
	new_tera.register_function("baseUrl", make_base_url());
	Ok(new_tera)
}

pub fn initialize() -> tera::Result<Tera> {
	let tera = Tera::new("static/templates/*")?;
	Ok(tera)
}

pub fn login_page(
	tera: &Tera,
	language: Language,
	mut translations: languages::Translations,
) -> Result<String, RawUnexpected> {
	translations.refresh()?;
	let mut tera = extend_tera(tera, language, translations)?;
	tera.full_reload()?;
	let context = tera::Context::new();
	tera.render("login.html", &context).unexpect()
}

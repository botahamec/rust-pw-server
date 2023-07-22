use std::collections::HashMap;
use std::path::PathBuf;

use actix_web::{get, web, HttpResponse, Scope};
use exun::RawUnexpected;
use ini::{Ini, Properties};
use raise::yeet;
use unic_langid::subtags::Language;

#[derive(Debug, Clone, PartialEq)]
pub struct Translations {
	languages: HashMap<Language, Properties>,
}

pub fn initialize() -> Result<Translations, RawUnexpected> {
	let mut translations = Translations {
		languages: HashMap::new(),
	};
	translations.refresh()?;
	Ok(translations)
}

impl Translations {
	pub fn languages(&self) -> Box<[Language]> {
		self.languages.keys().cloned().collect()
	}

	pub fn get_message(&self, language: Language, key: &str) -> Option<String> {
		Some(self.languages.get(&language)?.get(key)?.to_owned())
	}

	pub fn refresh(&mut self) -> Result<(), RawUnexpected> {
		let mut languages = HashMap::with_capacity(1);
		for entry in PathBuf::from("static/languages").read_dir()? {
			let entry = entry?;
			if entry.file_type()?.is_dir() {
				continue;
			}

			let path = entry.path();
			let Some(path) = path.file_name() else { yeet!(RawUnexpected::msg("Path ended with ..")) };
			let path = path.to_string_lossy();
			let Some(language) = path.as_bytes().get(0..2) else { yeet!(RawUnexpected::msg(format!("{} not long enough to be a language name", path))) };
			let language = Language::from_bytes(language)?;
			let messages = Ini::load_from_file(entry.path())?.general_section().clone();

			languages.insert(language, messages);
		}

		self.languages = languages;
		Ok(())
	}
}

#[get("")]
pub async fn all_languages(translations: web::Data<Translations>) -> HttpResponse {
	HttpResponse::Ok().json(
		translations
			.languages()
			.into_iter()
			.map(|l| l.as_str())
			.collect::<Box<[&str]>>(),
	)
}

pub fn languages() -> Scope {
	web::scope("/languages").service(all_languages)
}

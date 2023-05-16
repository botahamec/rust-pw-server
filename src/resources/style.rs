use std::path::{Path, PathBuf};

use actix_web::{get, http::StatusCode, web, HttpResponse, ResponseError};
use exun::{Expect, ResultErrorExt};
use grass::OutputStyle;
use raise::yeet;
use serde::Serialize;
use thiserror::Error;

fn output_style() -> OutputStyle {
	if cfg!(debug_assertions) {
		OutputStyle::Expanded
	} else {
		OutputStyle::Compressed
	}
}

fn options() -> grass::Options<'static> {
	grass::Options::default()
		.load_path("static/style")
		.style(output_style())
}

#[derive(Debug, Clone, Error, Serialize)]
pub enum LoadStyleError {
	#[error("The requested stylesheet was not found")]
	FileNotFound(Box<Path>),
}

impl ResponseError for LoadStyleError {
	fn status_code(&self) -> StatusCode {
		match self {
			Self::FileNotFound(..) => StatusCode::NOT_FOUND,
		}
	}
}

pub fn load(stylesheet: &str) -> Result<String, Expect<LoadStyleError>> {
	let options = options();
	let path = PathBuf::from(format!("static/style/{}.scss", stylesheet));
	if !path.exists() {
		yeet!(LoadStyleError::FileNotFound(path.into()).into());
	}
	let css = grass::from_path(format!("static/style/{}.scss", stylesheet), &options).unexpect()?;
	Ok(css)
}

#[get("/{stylesheet}.css")]
pub async fn get_css(stylesheet: web::Path<Box<str>>) -> Result<HttpResponse, LoadStyleError> {
	let css = load(&stylesheet).map_err(|e| e.unwrap())?;
	let response = HttpResponse::Ok().content_type("text/css").body(css);
	Ok(response)
}

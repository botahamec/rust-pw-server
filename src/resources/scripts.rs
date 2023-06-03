use std::path::Path;

use actix_web::{get, http::StatusCode, web, HttpResponse, ResponseError};
use exun::{Expect, ResultErrorExt};
use path_clean::clean;
use raise::yeet;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, Error, Serialize)]
pub enum LoadScriptError {
	#[error("The requested script does not exist")]
	FileNotFound(Box<Path>),
}

impl ResponseError for LoadScriptError {
	fn status_code(&self) -> StatusCode {
		match self {
			Self::FileNotFound(..) => StatusCode::NOT_FOUND,
		}
	}
}

fn load(script: &str) -> Result<String, Expect<LoadScriptError>> {
	let path = clean(format!("static/scripts/{}.js", script));
	if !path.exists() {
		yeet!(LoadScriptError::FileNotFound(path.into()).into());
	}
	let js = std::fs::read_to_string(format!("static/scripts/{}.js", script)).unexpect()?;
	Ok(js)
}

#[get("/{script}.js")]
pub async fn get_js(script: web::Path<Box<str>>) -> Result<HttpResponse, LoadScriptError> {
	let js = load(&script).map_err(|e| e.unwrap())?;
	let response = HttpResponse::Ok().content_type("text/javascript").body(js);
	Ok(response)
}

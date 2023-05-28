use std::collections::HashMap;

use actix_web::{web, HttpResponse};
use serde::Deserialize;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResponseType {
	Code,
	Token,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthorizationParameters {
	response_type: ResponseType,
	client_id: Uuid,
	redirect_uri: Url,
	state: Box<str>,

	#[serde(flatten)]
	additional_parameters: HashMap<Box<str>, Box<str>>,
}

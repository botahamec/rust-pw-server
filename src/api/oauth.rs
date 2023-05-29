use std::str::FromStr;

use actix_web::{get, post, web, HttpResponse, Scope};
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;
use tera::Tera;
use unic_langid::subtags::Language;
use url::Url;
use uuid::Uuid;

use crate::resources::{languages, templates};
use crate::services::{authorization, db};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResponseType {
	Code,
	Token,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationParameters {
	response_type: ResponseType,
	client_id: Uuid,
	redirect_uri: Option<Url>,
	scope: String, // TODO lol no
	state: Option<Box<str>>,
}

#[derive(Clone, Deserialize)]
struct AuthorizeCredentials {
	username: Box<str>,
	password: Box<str>,
}

#[post("/authorize")]
async fn authorize(
	db: web::Data<MySqlPool>,
	query: web::Query<AuthorizationParameters>,
	credentials: web::Form<AuthorizeCredentials>,
) -> HttpResponse {
	// TODO check that the URI is valid
	todo!()
}

#[get("/authorize")]
async fn authorize_page(
	db: web::Data<MySqlPool>,
	tera: web::Data<Tera>,
	translations: web::Data<languages::Translations>,
	query: web::Query<AuthorizationParameters>,
) -> HttpResponse {
	// TODO find a better way of doing languages
	// TODO check that the URI is valid
	let language = Language::from_str("en").unwrap();
	let page =
		templates::login_page(&tera, &query, language, translations.get_ref().clone()).unwrap();
	HttpResponse::Ok().content_type("text/html").body(page)
}

#[derive(Clone, Deserialize)]
#[serde(tag = "grant_type")]
enum GrantType {}

#[derive(Clone, Deserialize)]
struct TokenRequest {
	#[serde(flatten)]
	grant_type: GrantType,
	scope: String, // TODO lol no
}

#[post("/token")]
async fn token(
	db: web::Data<MySqlPool>,
	req: web::Form<TokenRequest>,
	authorization: web::Header<authorization::BasicAuthorization>, // TODO make this optional
) -> HttpResponse {
	todo!()
}

pub fn service() -> Scope {
	web::scope("/oauth")
		.service(authorize_page)
		.service(authorize)
		.service(token)
}

use actix_web::http::header::{self, HeaderValue};
use actix_web::middleware::{ErrorHandlerResponse, ErrorHandlers, Logger, NormalizePath};
use actix_web::web::Data;
use actix_web::{dev, App, HttpServer};

use exun::*;

mod api;
mod models;
mod resources;
mod services;

use resources::*;
use services::*;

fn error_content_language<B>(
	mut res: dev::ServiceResponse,
) -> actix_web::Result<ErrorHandlerResponse<B>> {
	res.response_mut()
		.headers_mut()
		.insert(header::CONTENT_LANGUAGE, HeaderValue::from_static("en"));

	Ok(ErrorHandlerResponse::Response(res.map_into_right_body()))
}

#[actix_web::main]
async fn main() -> Result<(), RawUnexpected> {
	// load the environment file, but only in debug mode
	#[cfg(debug_assertions)]
	dotenv::dotenv()?;

	// initialize the database
	let db_url = secrets::database_url()?;
	let sql_pool = db::initialize(&db_url).await?;

	let tera = templates::initialize()?;

	let translations = languages::initialize()?;

	// start the server
	HttpServer::new(move || {
		App::new()
			// middleware
			.wrap(ErrorHandlers::new().default_handler(error_content_language))
			.wrap(NormalizePath::trim())
			.wrap(Logger::new("\"%r\" %s %Dms"))
			// app shared state
			.app_data(Data::new(sql_pool.clone()))
			.app_data(Data::new(tera.clone()))
			.app_data(Data::new(translations.clone()))
			// frontend services
			// has to be first so they don't get overwritten by the "" scope
			.service(style::get_css)
			.service(scripts::get_js)
			.service(languages::languages())
			// api services
			.service(api::liveops())
			.service(api::users())
			.service(api::ops())
	})
	.shutdown_timeout(1)
	.bind(("127.0.0.1", 8080))?
	.run()
	.await?;

	Ok(())
}

use actix_web::http::header::{self, HeaderValue};
use actix_web::middleware::{DefaultHeaders, ErrorHandlerResponse, ErrorHandlers, Logger};
use actix_web::web::Data;
use actix_web::{dev, App, HttpServer};

use exun::*;

mod api;
mod models;
mod services;

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
	// initialize the database
	let db_url = secrets::database_url()?;
	let sql_pool = db::initialize(&db_url).await?;

	// start the server
	HttpServer::new(move || {
		App::new()
			.wrap(ErrorHandlers::new().default_handler(error_content_language))
			.wrap(Logger::new("[%t] \"%r\" %s %Dms"))
			.app_data(Data::new(sql_pool.clone()))
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

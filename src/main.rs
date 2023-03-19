use actix_web::{web::Data, App, HttpServer};
use exun::RawUnexpected;

mod api;
mod services;

use services::*;

#[actix_web::main]
async fn main() -> Result<(), RawUnexpected> {
	let sql_pool = db::initialize("password_database", "dbuser", "Demo1234").await?;
	HttpServer::new(move || {
		App::new()
			.app_data(Data::new(sql_pool.clone()))
			.service(api::liveops())
	})
	.shutdown_timeout(1)
	.bind(("127.0.0.1", 8080))?
	.run()
	.await?;

	Ok(())
}

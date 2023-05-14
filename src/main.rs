use actix_web::middleware::Logger;
use actix_web::web::Data;
use actix_web::{App, HttpServer};

use exun::*;

mod api;
mod models;
mod services;

use services::*;

#[actix_web::main]
async fn main() -> Result<(), RawUnexpected> {
	// initialize the database
	let db_url = secrets::database_url()?;
	let sql_pool = db::initialize(&db_url).await?;

	// start the server
	HttpServer::new(move || {
		App::new()
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

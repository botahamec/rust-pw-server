use actix_web::{get, web, HttpResponse, Scope};

#[get("ping")]
async fn ping() -> HttpResponse {
	HttpResponse::Ok().finish()
}

pub fn service() -> Scope {
	web::scope("liveops/").service(ping)
}

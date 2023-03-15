use actix_web::{get, web, Scope};

#[get("ping")]
async fn ping() -> &'static str {
	"pong"
}

pub fn service() -> Scope {
	web::scope("liveops/").service(ping)
}

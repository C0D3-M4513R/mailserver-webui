use crate::rocket::response::Return;
use crate::rocket::template::login::Login;

#[actix_web::get("/")]
pub async fn index_get(session_ref: actix_web::web::ReqData<Option<super::Session>>) -> Return {
    match &*session_ref {
        None => (actix_web::http::StatusCode::OK, Login{error: None}).into(),
        Some(_) => Return::redirect_to_value(actix_web::http::header::HeaderValue::from_static("/admin"))
    }
}


pub(in crate::rocket) mod private {
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct Login {
        pub email: String,
        pub password: String,
    }
}
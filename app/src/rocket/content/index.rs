use rocket::http::Status;
use crate::rocket::response::Return;
use crate::rocket::template::login::Login;

#[rocket::get("/")]
pub fn index_get(session: Option<super::Session>) -> Return {
    match session {
        None => (Status::Ok, Login{error: None}).into(),
        Some(_) => Return::Redirect(rocket::response::Redirect::to(rocket::uri!("/admin")))
    }
}


pub(in crate::rocket) mod private {
    #[derive(rocket::form::FromForm)]
    pub struct Login<'r> {
        pub email: &'r str,
        pub password: String,
    }
}
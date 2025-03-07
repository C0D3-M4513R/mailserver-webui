use std::borrow::Cow;

#[derive(rocket::response::Responder)]
pub enum Return {
    Status(rocket::http::Status),
    Content((rocket::http::Status, TypedContent<Cow<'static, str>>)),
    Json((rocket::http::Status, TypedContent<rocket::serde::json::Value>)),
    Redirect(rocket::response::Redirect),
}
impl Return {
    pub fn override_status(&mut self, status: rocket::http::Status) {
        match self {
            Return::Status(s) => *s = status,
            Return::Content((s, _)) => *s = status,
            Return::Json((s, _)) => *s = status,
            Return::Redirect(_) => {},
        }
    }
}
#[derive(rocket::response::Responder)]
pub struct TypedContent<T> {
    pub(super) content: T,
    pub(super) content_type: rocket::http::ContentType,
}
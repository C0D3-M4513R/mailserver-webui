use std::borrow::Cow;

#[derive(rocket::response::Responder)]
pub enum Return {
    Status(rocket::http::Status),
    Content((rocket::http::Status, TypedContent<Cow<'static, str>>)),
    Json((rocket::http::Status, TypedContent<rocket::serde::json::Value>)),
    Redirect(rocket::response::Redirect),
}

#[derive(rocket::response::Responder)]
pub struct TypedContent<T> {
    pub(super) content: T,
    pub(super) content_type: rocket::http::ContentType,
}
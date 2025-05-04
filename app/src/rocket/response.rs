use std::borrow::Cow;
use crate::rocket::template::error::TemplateError;

#[derive(rocket::response::Responder)]
pub enum Return {
    Status(rocket::http::Status),
    // Json((rocket::http::Status, TypedContent<rocket::serde::json::Value>)),
    Content((rocket::http::Status, TypedContent<Cow<'static, str>>)),
    Redirect(rocket::response::Redirect),
}
impl Return {
    pub fn override_status(&mut self, status: rocket::http::Status) {
        match self {
            Return::Status(s) => *s = status,
            // Return::Json((s, _)) => *s = status,
            Return::Content((s, _)) => *s = status,
            Return::Redirect(_) => {},
        }
    }
    pub fn override_content_type(&mut self, content_type: rocket::http::ContentType) {
        match self {
            Return::Content((_, content)) => content.content_type = content_type,
            _ => {},
        }
    }
}

impl<T: askama::Template> From<(rocket::http::Status, T)> for Return {
    fn from(value: (rocket::http::Status, T)) -> Self {
        match value.1.render().map_err(TemplateError::from) {
            Ok(v) => Return::Content((value.0, TypedContent::html(Cow::Owned(v)))),
            Err(e) => Return::Content((rocket::http::Status::InternalServerError, TypedContent::html(Cow::Owned(e.to_string())))),
        }
    }
}
#[derive(rocket::response::Responder)]
pub struct TypedContent<T> {
    pub(super) content: T,
    pub(super) content_type: rocket::http::ContentType,
}
impl<T> TypedContent<T> {
    pub const fn html(content: T) -> Self {
        Self { content, content_type: rocket::http::ContentType::HTML }
    }
}
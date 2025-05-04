use std::borrow::Cow;
use askama::Template;
use rocket::http::Status;
use crate::rocket::auth::session::Session;
use crate::rocket::messages::{SESSION_ISSUE, VIEW_ADMIN_PANEL_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::template::error::TemplateError;
use crate::rocket::template::login::Login;

#[rocket::get("/")]
pub async fn auth_check_login(
    session: Option<Session>,
) -> Return {
    let session = match session {
        None => return Return::Content((Status::Unauthorized, TypedContent::html(Cow::Owned(Login{error: Some(Cow::Borrowed(SESSION_ISSUE))}.render()
            .map_err(TemplateError::from)
            .unwrap_or_else(|a|a.to_string()))))),
        Some(v) => v,
    };

    if session.get_permissions().iter().any(|v|v.1.admin() || v.1.view_domain()) {
        Return::Status(Status::NoContent)
    } else {
        Return::Content((Status::Unauthorized, TypedContent::html(Cow::Owned(
            Login{error: Some(Cow::Borrowed(VIEW_ADMIN_PANEL_NO_PERM))}.render()
                .map_err(TemplateError::from)
                .unwrap_or_else(|a|a.to_string())
        ))))
    }
}
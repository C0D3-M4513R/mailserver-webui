use std::borrow::Cow;
use rocket::http::Status;
use crate::rocket::auth::session::Session;
use crate::rocket::messages::{SESSION_ISSUE, VIEW_ADMIN_PANEL_NO_PERM};
use crate::rocket::response::Return;
use crate::rocket::template::login::Login;

#[rocket::get("/")]
pub async fn auth_check_login(
    session: Option<Session>,
) -> Return {
    let session = match session {
        None => return (Status::Unauthorized, Login{error: Some(Cow::Borrowed(SESSION_ISSUE))}).into(),
        Some(v) => v,
    };

    if session.get_permissions().iter().any(|v|v.1.admin() || v.1.view_domain()) {
        Return::Status(Status::NoContent)
    } else {
        (Status::Unauthorized, Login{error: Some(Cow::Borrowed(VIEW_ADMIN_PANEL_NO_PERM))}).into()
    }
}
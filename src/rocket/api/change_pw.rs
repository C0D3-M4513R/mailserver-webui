use std::borrow::Cow;
use super::super::auth::check_password::{check_password, Error as CheckPasswordError};
use crate::rocket::messages::{DATABASE_TRANSACTION_ERROR, INCORRECT_PASSWORD, SELF_CHANGE_PASSWORD_ERROR, SELF_CHANGE_PASSWORD_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::session::Session;
use super::super::content::change_pw::{HEAD, FORM, TAIL};

mod private {
    #[derive(rocket::form::FromForm)]
    pub struct ChangePw{
        pub(super) old_password: String,
        pub(super) new_password: String,
        pub(super) new_password1: String,
    }
}

#[rocket::put("/admin/change_pw", data = "<data>")]
pub async fn admin_put_change_pw(session: Option<Session>, data: rocket::form::Form<private::ChangePw>) -> Return {
    let session = match session {
        None => return Return::Redirect(rocket::response::Redirect::to(rocket::uri!("/"))),
        Some(v) => v,
    };

    if !session.get_self_change_password() {
        return Return::Content((rocket::http::Status::Forbidden, TypedContent {
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Borrowed(const_format::concatcp!(HEAD,SELF_CHANGE_PASSWORD_NO_PERM, TAIL))
        }));
    }

    if data.new_password != data.new_password1 {
        return Return::Content((rocket::http::Status::Ok, TypedContent {
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Borrowed(const_format::concatcp!(HEAD, r#"<div class="error">The new passwords don't match</div>"#, FORM, TAIL))
        }));
    }

    match check_password(session.get_user_id(), data.old_password.as_str(), Some(data.new_password.as_str())).await {
        Ok(()) => Return::Content((rocket::http::Status::Ok, TypedContent {
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Borrowed(const_format::concatcp!(HEAD, r#"<div class="success">The password was changed successfully</div>"#, FORM, TAIL))
        })),
        Err(CheckPasswordError::VerifyPassword(err)) => {
            #[cfg(debug_assertions)]
            log::debug!("Password incorrect: {err}");
            Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Borrowed(const_format::concatcp!(HEAD, INCORRECT_PASSWORD, FORM, TAIL)),
            }))
        }
        Err(CheckPasswordError::TransactionBegin(err)) | Err(CheckPasswordError::TransactionCommit(err)) => {
            log::debug!("Error beginning or commiting transaction to database: {err}!");
            Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Borrowed(const_format::concatcp!(HEAD, DATABASE_TRANSACTION_ERROR, TAIL)),
            }))
        }
        Err(err) => {
            #[cfg(debug_assertions)]
            log::debug!("Error changing password: {err}");
            Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Borrowed(const_format::concatcp!(HEAD, SELF_CHANGE_PASSWORD_ERROR, TAIL)),
            }))
        }
    }
}
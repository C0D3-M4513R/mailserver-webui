use rocket::http::CookieJar;
use super::super::auth::check_password::{check_password, Error as CheckPasswordError};
use crate::rocket::messages::{GET_PERMISSION_ERROR, INCORRECT_PASSWORD, SELF_CHANGE_PASSWORD_ERROR, SELF_CHANGE_PASSWORD_NO_PERM};
use crate::rocket::response::Return;
use crate::rocket::auth::session::Session;
use crate::rocket::template::change_pw::ChangePw;

mod private {
    #[derive(rocket::form::FromForm)]
    pub struct ChangePw{
        pub(super) old_password: String,
        pub(super) new_password: String,
        pub(super) new_password1: String,
    }
}

#[rocket::put("/admin/change_pw", data = "<data>")]
pub async fn admin_put_change_pw(session: Option<Session>, data: rocket::form::Form<private::ChangePw>, cookie_jar: &'_ CookieJar<'_>) -> Return {
    let mut session = match session {
        None => return Return::Redirect(rocket::response::Redirect::to(rocket::uri!("/"))),
        Some(v) => v,
    };

    let pool = crate::get_db().await;
    match session.refresh_permissions(pool.clone(), cookie_jar).await{
        Ok(()) => {},
        Err(err) => {
            log::error!("Error refreshing permissions: {err}");
            return (rocket::http::Status::InternalServerError, ChangePw{
                block_change_pw: true,
                error: Some(GET_PERMISSION_ERROR.into()),
            }).into();
        }
    }
    if !session.get_user_permission().self_change_password() {
        return (rocket::http::Status::Forbidden, ChangePw{
            block_change_pw: true,
            error: Some(SELF_CHANGE_PASSWORD_NO_PERM.into())
        }).into();
    }

    let data = data.into_inner();

    if data.new_password != data.new_password1 {
        return (rocket::http::Status::Ok, ChangePw{
            block_change_pw: false,
            error: Some(r#"<div class="error">The new passwords don't match</div>"#.into())
        }).into();
    }

    match check_password(pool, session.get_user_id(), session.get_user_id(), data.old_password, Some(data.new_password)).await {
        Ok(()) => (rocket::http::Status::Ok, ChangePw{
            block_change_pw: false,
            error: Some(r#"<div class="success">The password was changed successfully</div>"#.into())
        }).into(),
        Err(CheckPasswordError::VerifyPassword(err)) => {

            log::debug!("Password incorrect: {err}");
            (rocket::http::Status::InternalServerError, ChangePw{
                block_change_pw: false,
                error: Some(INCORRECT_PASSWORD.into()),
            }).into()
        }
        Err(err) => {

            log::debug!("Error changing password: {err}");
            (rocket::http::Status::InternalServerError, ChangePw{
                block_change_pw: true,
                error: Some(SELF_CHANGE_PASSWORD_ERROR.into()),
            }).into()
        }
    }
}
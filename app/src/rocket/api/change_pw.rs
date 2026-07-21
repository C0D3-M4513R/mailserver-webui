use super::super::auth::check_password::{check_password, Error as CheckPasswordError};
use crate::rocket::messages::{GET_PERMISSION_ERROR, INCORRECT_PASSWORD, SELF_CHANGE_PASSWORD_ERROR, SELF_CHANGE_PASSWORD_NO_PERM};
use crate::rocket::response::Return;
use crate::rocket::auth::session::Session;
use crate::rocket::template::change_pw::ChangePw;

mod private {
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct ChangePw{
        pub(super) old_password: String,
        pub(super) new_password: String,
        pub(super) new_password1: String,
    }
}

#[actix_web::post("/admin/change_pw")]
pub async fn admin_put_change_pw(session_ref: actix_web::web::ReqData<Option<Session>>, data: actix_web::web::Form<private::ChangePw>, key: actix_web::web::Data<actix_web::cookie::Key>) -> Return {
    let session = match &*session_ref {
        None => return Return::redirect_to_value(actix_web::http::header::HeaderValue::from_static("/")),
        Some(v) => v,
    };
    let mut session = session.clone();

    let mut cookie_jar = actix_web::cookie::CookieJar::new();
    let mut private = cookie_jar.private_mut(&*key);
    
    let pool = crate::get_db().await;
    match session.refresh_permissions(pool.clone(), &mut private).await{
        Ok(()) => {},
        Err(err) => {
            log::error!("Error refreshing permissions: {err}");
            return (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, ChangePw{
                block_change_pw: true,
                error: Some(GET_PERMISSION_ERROR.into()),
            }).into();
        }
    }
    if !session.get_user_permission().self_change_password() {
        return (actix_web::http::StatusCode::FORBIDDEN, ChangePw{
            block_change_pw: true,
            error: Some(SELF_CHANGE_PASSWORD_NO_PERM.into())
        }).into();
    }

    let data = data.into_inner();

    if data.new_password != data.new_password1 {
        return (actix_web::http::StatusCode::OK, ChangePw{
            block_change_pw: false,
            error: Some(r#"<div class="error">The new passwords don't match</div>"#.into())
        }).into();
    }

    match check_password(pool, session.get_user_id(), session.get_user_id(), data.old_password, Some(data.new_password)).await {
        Ok(()) => (actix_web::http::StatusCode::OK, ChangePw{
            block_change_pw: false,
            error: Some(r#"<div class="success">The password was changed successfully</div>"#.into())
        }).into(),
        Err(CheckPasswordError::VerifyPassword(err)) => {

            log::debug!("Password incorrect: {err}");
            (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, ChangePw{
                block_change_pw: false,
                error: Some(INCORRECT_PASSWORD.into()),
            }).into()
        }
        Err(err) => {

            log::debug!("Error changing password: {err}");
            (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, ChangePw{
                block_change_pw: true,
                error: Some(SELF_CHANGE_PASSWORD_ERROR.into()),
            }).into()
        }
    }
}
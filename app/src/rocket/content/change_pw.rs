use std::borrow::Cow;
use crate::rocket::template::change_pw::ChangePw;
use super::{Session, Return};
use super::super::messages::SELF_CHANGE_PASSWORD_NO_PERM;

#[actix_web::get("/admin/change_pw")]
pub async fn admin_get_change_pw(session_ref: actix_web::web::ReqData<Option<Session>>) -> Return {
    let session = match &*session_ref {
        None => return Return::redirect_to_value(actix_web::http::header::HeaderValue::from_static("/")),
        Some(v) => v,
    };

    if !session.get_user_permission().self_change_password() {
        return (actix_web::http::StatusCode::FORBIDDEN, ChangePw{
                error: Some(Cow::Borrowed(SELF_CHANGE_PASSWORD_NO_PERM)),
                block_change_pw: true
            }).into();
    }


    (actix_web::http::StatusCode::OK, ChangePw{
        error: None,
        block_change_pw: false
    }).into()
}


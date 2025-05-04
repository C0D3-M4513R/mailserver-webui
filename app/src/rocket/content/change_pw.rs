use std::borrow::Cow;
use crate::rocket::template::change_pw::ChangePw;
use super::{Session, Return};
use super::super::messages::SELF_CHANGE_PASSWORD_NO_PERM;

#[rocket::get("/admin/change_pw")]
pub async fn admin_get_change_pw(session: Option<Session>) -> Return {
    let session = match session {
        None => return Return::Redirect(rocket::response::Redirect::to(rocket::uri!("/"))),
        Some(v) => v,
    };

    if !session.get_user_permission().self_change_password() {
        return (rocket::http::Status::Forbidden, ChangePw{
                error: Some(Cow::Borrowed(SELF_CHANGE_PASSWORD_NO_PERM)),
                block_change_pw: true
            }).into();
    }


    (rocket::http::Status::Ok, ChangePw{
        error: None,
        block_change_pw: false
    }).into()
}


use std::borrow::Cow;
use crate::rocket::template::change_pw::ChangePw;
use super::{Session, Return, SESSION_HEADER};
use super::super::messages::SELF_CHANGE_PASSWORD_NO_PERM;

pub(in crate::rocket) const HEAD:&str = const_format::formatcp!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="color-scheme" content="light dark">
    <title>Password-Change</title>
</head>
<body>
    <h1>Password-Change</h1>
    {SESSION_HEADER}
    <a href="/admin">Main-Panel</a>"#
);
pub(in crate::rocket) const FORM:&str = r#"
    <form method="POST">
        <input type="hidden" name="_method" value="PUT"/>
        <label>Old Password: <input type="password" name="old_password"/></label>
        <label>New Password: <input type="password" name="new_password"/></label>
        <label>Confirm New Password: <input type="password" name="new_password1"/></label>
        <input type="submit"/ value="Submit">
    </form>
            "#;
pub(in crate::rocket) const TAIL:&str = r#"
</body>
</html>
            "#;
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


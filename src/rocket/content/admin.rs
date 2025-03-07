pub mod domain;

pub use domain::{admin_domain_get, admin_domain_accounts_get, admin_domain_account_get};

use super::{Return, TypedContent, Session, SESSION_HEADER};
use std::borrow::Cow;

#[rocket::get("/admin")]
pub async fn admin_get(session: Option<Session>) -> Return {
    let session = match session {
        None => return Return::Redirect(rocket::response::Redirect::to(rocket::uri!("/"))),
        Some(v) => v,
    };

    let mut domain_list = String::new();
    let mut permissions = session.get_permissions().iter().collect::<Vec<_>>();
    permissions.sort_by_key(|(k, _)| *k);
    for (domain, permissions) in permissions {
        if !permissions.get_web_login() || !permissions.get_view_domain() {
            continue;
        }
        domain_list.push_str(&format!(r#"<li><a href="/admin/{domain}/view">{domain}</a></li>"#));
    }

    Return::Content((rocket::http::Status::Ok, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Admin</title>
</head>
<body>
    <h1>Admin</h1>
    {SESSION_HEADER}

    <p>Welcome to the admin page</p>
    <p>Managable Domains:</p>
    <ul>{domain_list}</ul>
</body>
</html>
        "#))
    }))
}
pub mod domain;

pub use domain::{admin_domain_get, admin_domain_accounts_get, admin_domain_account_get, admin_domain_subdomains_get, admin_domain_permissions_get, admin_domain_aliases_get};

use super::{Return, TypedContent, Session, SESSION_HEADER};
use std::borrow::Cow;
use crate::rocket::auth::session::Permission;
use crate::rocket::content::email_settings::SETTINGS;
pub(super) fn sort_permissions(permissions: &std::collections::HashMap<String, Permission>) -> Vec<(&String, &Permission)> {
    let mut permissions = permissions.iter().collect::<Vec<_>>();
    permissions.sort_by(|(k1, p1), (k2, p2)| {
        (p1.domain_level(), k1).cmp(&(p2.domain_level(), k2))
    });
    permissions
}
#[rocket::get("/admin")]
pub async fn admin_get(session: Option<Session>) -> Return {
    let session = match session {
        None => return Return::Redirect(rocket::response::Redirect::to(rocket::uri!("/"))),
        Some(v) => v,
    };

    let mut domain_list = String::new();
    let permissions = sort_permissions(session.get_permissions());
    for (domain, permissions) in permissions {
        if !permissions.admin() && !permissions.view_domain() {
            continue;
        }
        domain_list.push_str(&format!(r#"<li><a href="/admin/{domain}">{domain}</a></li>"#));
    }

    Return::Content((rocket::http::Status::Ok, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="color-scheme" content="light dark">
    <title>Admin</title>
</head>
<body>
    <h1>Admin</h1>
    {SESSION_HEADER}

    <p>Welcome to the admin page</p>
    <p>Managable Domains:</p>
    <ul>{domain_list}</ul>
    {SETTINGS}
</body>
</html>
        "#))
    }))
}
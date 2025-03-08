pub mod accounts;
pub mod account;
pub mod subdomains;

pub use account::admin_domain_account_get;
pub use accounts::admin_domain_accounts_get;
pub use subdomains::admin_domain_subdomains_get;

use crate::rocket::session::HEADER;
use std::borrow::Cow;
use std::fmt::Display;
use super::super::{Session, Return, TypedContent};

pub(in crate::rocket) fn template(domain: &str, content: impl Display) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <title>{domain}'s Mail-Admin-Panel</title>
</head>
<body>
    <h1>{domain}'s Mail-Admin-Panel</h1>
    {HEADER}
    <p>Welcome to the admin page</p>
    {content}
</body>
</html>"#
    )
}
fn domain_linklist(session: &Session, domain: &str) -> String {
    let list_accounts;
    let list_permissions;
    let list_subdomain;
    match session.get_permissions().get(domain) {
        Some(v) => {
            list_permissions = v.get_admin() || v.get_list_permissions();
            list_accounts = v.get_admin() || v.get_list_accounts();
            list_subdomain = v.get_admin() || v.get_list_subdomain();
        }
        None => {
            list_permissions = false;
            list_accounts = false;
            list_subdomain = false;
        }
    }
    let accounts = if list_accounts {
        format!(r#"<a href="/admin/{domain}/accounts">Manage Accounts</a>"#)
    } else {
        String::new()
    };
    let permissions = if list_permissions {
        format!(r#"<a href="/admin/{domain}/permissions">Manage Permissions</a>"#)
    } else {
        String::new()
    };
    let subdomain = if list_subdomain {
        format!(r#"<a href="/admin/{domain}/subdomains">Manage Subdomains</a>"#)
    } else {
        String::new()
    };

    format!(
        r#"
            <div class="header">
                <a href="/admin">Back to Main-Panel</a>
                <a href="/admin/{domain}/view">Domain Main Overview</a>
                {accounts}
                {permissions}
                {subdomain}
            </div>
        "#
    )
}
#[rocket::get("/admin/<domain>/view")]
pub async fn admin_domain_get(session: Option<Session>, domain: &str) -> Return {
    let session = match session {
        None => return Return::Redirect(rocket::response::Redirect::to(rocket::uri!("/"))),
        Some(v) => v,
    };
    let unauth_error = template(domain, r#"<p>You are unable to access the Admin-Panel for this domain.</p>"#);
    let permissions = match session.get_permissions().get(domain) {
        None => return Return::Content((rocket::http::Status::Forbidden, TypedContent{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(unauth_error),
        })),
        Some(v) => v,
    };

    if !permissions.get_admin() && !permissions.get_view_domain() {
        return Return::Content((rocket::http::Status::Forbidden, TypedContent{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(unauth_error),
        }));
    }

    let header = domain_linklist(&session, domain);
    Return::Content((rocket::http::Status::Ok, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <title>{domain}'s Mail-Admin-Panel</title>
</head>
<body>
    <h1>{domain}'s Mail-Admin-Panel</h1>
    {HEADER}
    <p>Welcome to the admin page</p>
    {header}
    <h2>Rename Domain:</h2>
    <form method="POST" action="{domain}/name">
        <input type="hidden" name="_method" value="PUT" />
        <input type="text" name="name" value={domain}"/>
        <input type="submit" value="Rename Domain"/>
    </form>
    <p>Content could be here.</p>
</body>
</html>
        "#)),
    }))
}
pub(in crate::rocket) fn unauth_error(domain: &str) -> String {
    template(domain, r#"<p>You are unable to access the Admin-Panel for the domain {domain}.</p>"#)
}

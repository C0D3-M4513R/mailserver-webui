pub mod accounts;
pub mod account;
pub mod subdomains;
pub mod permissions;

pub use account::admin_domain_account_get;
pub use accounts::admin_domain_accounts_get;
pub use subdomains::admin_domain_subdomains_get;
pub use permissions::admin_domain_permissions_get;

use crate::rocket::auth::session::HEADER;
use std::borrow::Cow;
use std::fmt::Display;
use crate::rocket::messages::{DATABASE_ERROR, VIEW_DOMAIN_NO_PERM};
use super::super::{Session, Return, TypedContent};

pub(in crate::rocket) fn template(domain: &str, content: impl Display) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="color-scheme" content="light dark">
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
            list_permissions = v.admin() || v.list_permissions();
            list_accounts = v.admin() || v.list_accounts();
            list_subdomain = v.admin() || v.list_subdomain();
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
                <a href="/admin/{domain}">Domain Main Overview</a>
                {accounts}
                {permissions}
                {subdomain}
            </div>
        "#
    )
}
#[rocket::get("/admin/<domain>")]
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

    if !permissions.admin() && !permissions.view_domain() {
        return Return::Content((rocket::http::Status::Forbidden, TypedContent{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(template(domain, VIEW_DOMAIN_NO_PERM)),
        }));
    }

    let db = crate::get_mysql().await;
    let manage_domain = if permissions.admin() || permissions.modify_domain() {
        let name = match sqlx::query!(r#"
SELECT
    domains.name AS "name!",
    super_domains.name AS "super_domain!"
FROM domains
JOIN virtual_domains super_domains ON domains.super = super_domains.id
WHERE domains.id = $1
"#, permissions.domain_id())
            .fetch_one(db)
            .await
        {
            Err(err) => {
                log::debug!("Error fetching domain: {err}");
                return Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                    content_type: rocket::http::ContentType::HTML,
                    content: Cow::Owned(template(domain, DATABASE_ERROR)),
                }));
            },
            Ok(v) => v
        };
        let super_domain = name.super_domain;
        let name = name.name;
        format!(r#"
    <form method="POST" action="./name">
        <input type="hidden" name="_method" value="PUT" />
        <label>New Name:<a><input type="text" name="name" value="{name}"/>.{super_domain}</a></label>
        <input type="submit" value="Rename Domain"/>
    </form>
    "#)
    } else {
        String::new()
    };

    let manage_domain = {
        let domain_accepts_email = if permissions.domain_accepts_email() { "checked" } else {""};
        let view_only = if !permissions.admin() && !permissions.modify_domain() { "disabled" } else {""};
        format!(r#"
<form method="POST" action="./accepts_email">
    <input type="hidden" name="_method" value="PUT" />
    <label>Accepts Email: <input type="checkbox" name="accepts_email" {domain_accepts_email} {view_only}/></label>
    <input type="submit" value="Update Accepts Email" {view_only}/>
</form>
{manage_domain}
"#)
    };
    let owner = if permissions.is_owner() {
        let accounts = match sqlx::query!(r#"
WITH owner_domains AS (
    SELECT id, name FROM virtual_domains WHERE $1 = ANY(domain_owner)
    UNION
    SELECT domain_id as id, domain_name as name FROM flattened_web_domain_permissions perms WHERE user_id = $1 AND (perms.admin OR perms.list_accounts)
) SELECT
    users.id AS "id!",
    users.email AS "email!",
    owner_domains.name AS "domain!",
    (users.id = domains.domain_owner[1]) as "true_owner!"
FROM owner_domains
    JOIN virtual_users users ON users.domain_id = owner_domains.id
    JOIN flattened_domains domains ON $2 = domains.id
"#, session.get_user_id(), permissions.domain_id())
            .fetch_all(db)
            .await
        {
            Err(err) => {
                log::debug!("Error fetching accounts: {err}");
                return Return::Content((rocket::http::Status::Forbidden, TypedContent{
                    content_type: rocket::http::ContentType::HTML,
                    content: Cow::Owned(template(domain, VIEW_DOMAIN_NO_PERM)),
                }));
            },
            Ok(v) => {
                v.into_iter().map(|v|{
                    let id = v.id;
                    let domain = v.domain;
                    let selected = if v.true_owner {
                        r#"selected="selected""#
                    } else {""};
                    let email = v.email;
                    format!(r#"<option value="{id}" {selected}>{email}@{domain}</option>"#)
                })
                    .fold(String::new(), |mut a, b|{a.push_str(&b); a})
            }
        };
        if !accounts.is_empty() {
            format!(r#"
<h2>Change Owner:</h2>
    <form action="./owner" method="POST">
    <input type="hidden" name="_method" value="PUT" />
    <select name="owner">
        {accounts}
    </select>
    <input type="submit" value="Change Owner"/>
    </form>
            "#)
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    let header = domain_linklist(&session, domain);
    Return::Content((rocket::http::Status::Ok, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, format!(r#"
{header}
<h2>Manage Domain:</h2>
{manage_domain}
{owner}
        "#))),
    }))
}
pub(in crate::rocket) fn unauth_error(domain: &str) -> String {
    template(domain, format!(r#"<p>You are unable to access the Admin-Panel for the domain {domain}.</p>"#))
}

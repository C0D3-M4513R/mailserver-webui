pub mod accounts;
pub mod account;
pub mod subdomains;
pub mod permissions;
pub mod aliases;

pub use account::admin_domain_account_get;
pub use accounts::admin_domain_accounts_get;
pub use subdomains::admin_domain_subdomains_get;
pub use permissions::admin_domain_permissions_get;
pub use aliases::admin_domain_aliases_get;

use crate::rocket::auth::session::HEADER;
use std::fmt::Display;
use crate::rocket::messages::{DATABASE_ERROR, VIEW_ADMIN_PANEL_DOMAIN_NO_PERM, VIEW_DOMAIN_NO_PERM};
use crate::rocket::template::authenticated::domain_base::DomainBase;
use crate::rocket::template::authenticated::domain::index::{Dkim, DkimKey, DomainAccount, DomainIndex, DomainName};
use super::super::{Session, Return};

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
    let list_aliases;
    match session.get_permissions().get(domain) {
        Some(v) => {
            list_permissions = v.admin() || v.list_permissions();
            list_accounts = v.admin() || v.list_accounts();
            list_subdomain = v.admin() || v.list_subdomain();
            list_aliases = v.admin() || v.list_alias();
        }
        None => {
            list_permissions = false;
            list_accounts = false;
            list_subdomain = false;
            list_aliases = false;
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
    let aliases = if list_aliases {
        format!(r#"<a href="/admin/{domain}/aliases">Manage Aliases</a>"#)
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
                {aliases}
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
    let permissions = match session.get_permissions().get(domain) {
        None => return (rocket::http::Status::Forbidden, DomainBase{
            domain,
            content: VIEW_ADMIN_PANEL_DOMAIN_NO_PERM,
        }).into(),
        Some(v) => v,
    };

    if !permissions.admin() && !permissions.view_domain() {
        return (rocket::http::Status::Forbidden, DomainBase{
            domain,
            content: VIEW_DOMAIN_NO_PERM,
        }).into();
    }

    let db = crate::get_db().await;
    let rename = if permissions.admin() || permissions.modify_domain() {
        let name = match sqlx::query!(r#"
SELECT
domains.name AS "name!",
super_domains.name AS "super_domain!"
FROM domains
JOIN virtual_domains super_domains ON domains.super = super_domains.id
WHERE domains.id = $1
"#, permissions.domain_id())
            .fetch_one(&db)
            .await
        {
            Err(err) => {
                log::debug!("Error fetching domain: {err}");
                return (rocket::http::Status::InternalServerError, DomainBase {
                    domain,
                    content: DATABASE_ERROR,
                }).into();
            },
            Ok(v) => v
        };
        let super_domain = name.super_domain;
        let name = name.name;
        Some(DomainName{
            self_name: name,
            super_name: super_domain,
        })
    } else {
        None
    };
    let owner = if permissions.is_owner() {
        match sqlx::query!(r#"
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
            .fetch_all(&db)
            .await
        {
            Err(err) => {
                log::debug!("Error fetching accounts: {err}");
                return (rocket::http::Status::Forbidden, DomainBase{
                    domain,
                    content: VIEW_DOMAIN_NO_PERM,
                }).into();
            },
            Ok(v) => {
                v.into_iter().map(|v|DomainAccount{
                    id: v.id,
                    true_owner: v.true_owner,
                    email: v.email,
                    domain: v.domain,
                }).collect::<Vec<_>>()
            }
        }
    } else {
        Vec::new()
    };
    let dkim = if permissions.admin() || permissions.modify_domain() {
        let res = match sqlx::query!("SELECT selector, private_key, active FROM dkim WHERE domain_id = $1", permissions.domain_id())
            .fetch_all(&db)
            .await {
            Ok(v) => v,
            Err(err) => {
                log::debug!("Error fetching domain dkim data: {err}");
                return (rocket::http::Status::InternalServerError, DomainBase {
                    domain,
                    content: DATABASE_ERROR,
                }).into();
            },
        };
        Some(res.into_iter().map(|v|{
            let key = DkimKey::from_data(&v.private_key);
            Dkim{
                selector: v.selector,
                domain: domain.to_string(),
                key,
                active: v.active,
            }
        }).collect())
    } else {None};
    (rocket::http::Status::Ok, DomainIndex{
        domain,
        permissions,
        rename,
        accounts: owner,
        dkim
    }).into()
}
pub(crate) const UNAUTH:fn(&str) -> (rocket::http::Status, DomainBase<'_, &'static str>) = |domain| (rocket::http::Status::Forbidden, DomainBase{
    domain,
    content: VIEW_DOMAIN_NO_PERM,
});
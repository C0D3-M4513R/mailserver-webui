use std::borrow::Cow;
use crate::rocket::content::admin::domain::{domain_linklist, template, unauth_error};
use crate::rocket::messages::{DATABASE_ERROR, LIST_ACCOUNT_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::Session;

#[rocket::get("/admin/<domain>/accounts")]
pub async fn admin_domain_accounts_get(session: Option<Session>, domain: &str) -> Return {
    admin_domain_accounts_get_impl(session, domain, None).await
}

pub(in crate::rocket) async fn admin_domain_accounts_get_impl(session: Option<Session>, domain: &str, error: Option<&str>) -> Return {
    let session = match session {
        None => return Return::Content((rocket::http::Status::Forbidden, TypedContent{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(unauth_error(domain)),
        })),
        Some(v) => v,
    };
    let no_perm = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, LIST_ACCOUNT_NO_PERM)),
    }));
    let permissions = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };

    if !permissions.admin() {
        if
            !permissions.view_domain() ||
            !permissions.list_accounts()
        {
            return no_perm;
        }
    }

    let db = crate::get_mysql().await;
    let accounts = match sqlx::query!(r#"
SELECT
    users.id AS "id!",
    users.email AS "email!"
FROM virtual_users users
WHERE users.domain_id = $1"#, permissions.domain_id())
        .fetch_all(db)
        .await
    {
        Ok(v) => v.into_iter().map(|v|{
            let id = v.id;
            let email = v.email;
            let full_email = format!("{email}@{domain}");
            let modify = if permissions.admin() || permissions.modify_accounts() {
                format!(r#"<a href="/admin/{domain}/accounts/{email}">Modify</a>"#)
            } else {
                String::new()
            };

            format!(r#"<tr><td><input class="account-select" type="checkbox" name="accounts[{id}]"/></td><td>{full_email}</td><td>{modify}</td></tr>"#)
        }).fold(String::new(), |a,b|format!("{a}{b}")),
        Err(err) => {

            log::error!("Error fetching accounts: {err}");
            return Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(template(domain, DATABASE_ERROR)),
            }));
        }
    };
    let deleted_accounts = if permissions.admin() || permissions.list_deleted() {
        match sqlx::query!(r#"
SELECT
    users.id AS "id!",
    users.email AS "email!"
FROM users
WHERE users.domain_id = $1 AND deleted = true"#, permissions.domain_id())
            .fetch_all(db)
            .await
        {
            Ok(v) => {
                if v.is_empty() {
                    String::new()
                } else {
                    let deleted_accounts = v.into_iter().map(|v|{
                        let id = v.id;
                        let email = v.email;
                        let full_email = format!("{email}@{domain}");

                        format!(r#"<tr><td><input class="account-select" type="checkbox" name="accounts[{id}]"/></td><td>{full_email}</td></tr>"#)
                    }).fold(String::new(), |a,b|format!("{a}{b}"));
                    format!(r#"<h2>Disabled Accounts:</h2>
                    <form method="POST">
                    <button type="submit" formaction="accounts/restore">Restore Selected Accounts</button>
                    <button type="submit" formaction="accounts/delete">Permanently Delete Selected Accounts</button>
                    <table>
                        <tr><th>Selected</th><th>Email</th></tr>
                    {deleted_accounts}
                    </table></form>
                    "#)
                }
            },
            Err(err) => {

                log::error!("Error fetching deleted accounts: {err}");
                const DISABLED_ACCOUNTS_DB_ERROR:&str = const_format::concatcp!("<h2>Disabled Accounts:</h2><p>", DATABASE_ERROR, "</p>");
                DISABLED_ACCOUNTS_DB_ERROR.to_string()
            }
        }
    } else {
        String::new()
    };

    let new_account = if permissions.admin() || permissions.create_accounts() {
        format!(r#"<h2>Create new Account:</h2>
<form method="POST">
    <input type="hidden" name="_method" value="PUT" />
    <label>Email: <a></a><input type="text" name="email" pattern="[a-zA-Z0-9\(\)\*\,\-\.\[\]\_]+" />@{domain}</a></label><br>
    <label>Password: <input type="password" name="password" /></label><br>
    <input type="submit" value="Add Account" />
</form>"#)
    } else {
        String::new()
    };

    let delete = if permissions.admin() || permissions.delete_accounts(){
        r#"<input type="hidden" name="_method" value="DELETE" /><input type="submit" value="Disable Selected Accounts" />"#
    } else {
        ""
    };
    let header = domain_linklist(&session, domain);
    let error = error.unwrap_or("");
    Return::Content((rocket::http::Status::Ok, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, format!(r#"
    {header}
<div id="account-mod-error">{error}</div>
{new_account}
<table><tr><td>
<h2>Existing Accounts:</h2>
<form method="POST">
{delete}
    <table>
        <tr>
            <th>Selected</th>
            <th>Email</th>
            <th>Actions</th>
        </tr>
        {accounts}
    </table>
</form>
</td><td>{deleted_accounts}</td></tr></table>
        "#).as_str())),
    }))
}
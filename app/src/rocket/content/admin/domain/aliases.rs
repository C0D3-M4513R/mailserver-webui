use std::borrow::Cow;
use crate::rocket::content::admin::domain::{domain_linklist, template, unauth_error};
use crate::rocket::messages::{DATABASE_ERROR, LIST_ACCOUNT_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::Session;

#[rocket::get("/admin/<domain>/aliases")]
pub async fn admin_domain_aliases_get(session: Option<Session>, domain: &str) -> Return {
    admin_domain_aliases_get_impl(session, domain, None).await
}

pub(in crate::rocket) async fn admin_domain_aliases_get_impl(session: Option<Session>, domain: &str, error: Option<&str>) -> Return {
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
            !permissions.list_alias()
        {
            return no_perm;
        }
    }

    let db = crate::get_mysql().await;
    let aliases = match sqlx::query!(r#"
SELECT
    alias.id AS "id!",
    alias.source AS "source!",
    users.username AS "email!"
FROM virtual_aliases alias
JOIN dovecot_users users ON alias.destination = users.id
WHERE alias.domain_id = $1"#, permissions.domain_id())
        .fetch_all(db)
        .await
    {
        Ok(v) => v.into_iter().map(|v|{
            let id = v.id;
            let source = v.source;
            let email = v.email;
            let full_email = format!("{source}@{domain}");

            format!(r#"<tr><td><input class="account-select" type="checkbox" name="aliases[{id}]"/></td><td>{full_email}</td><td>{email}</td></tr>"#)
        }).fold(String::new(), |a,b|format!("{a}{b}")),
        Err(err) => {

            log::error!("Error fetching accounts: {err}");
            return Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(template(domain, DATABASE_ERROR)),
            }));
        }
    };

    let new_account = if permissions.admin() || permissions.create_alias() {
        let has_err;
        let destination = match sqlx::query!(r#"SELECT users.id as "id!", users.email || '@' || domains.name as "username!" FROM virtual_users users
    JOIN virtual_domains domains ON users.domain_id = domains.id
    JOIN flattened_web_domain_permissions perms ON perms.user_id = $1 AND perms.domain_id = users.domain_id
WHERE $1 = ANY(domains.domain_owner) OR perms.admin OR perms.list_accounts
"#, session.get_user_id()).fetch_all(db).await
        {
            Ok(v) => {
                has_err = false;
                v.into_iter().map(|v|{
                    let id = v.id;
                    let username = v.username;
                    format!(r#"<option value="{id}">{username}</option>"#)
                }).reduce(|a,b|format!("{a}{b}"))
                    .unwrap_or_default()
            },
            Err(err) => {
                has_err = true;
                log::error!("Error fetching users for alias create: {err}");
                const OPTION_DB_ERROR:&str = const_format::concatcp!(r#"<option disabled>"#,DATABASE_ERROR, r#"</option>"#);
                OPTION_DB_ERROR.to_string()
            }
        };
        let has_err = if has_err { "disabled" } else {""};

        format!(r#"<h2>Create new Alias:</h2>
<form method="POST">
    <input type="hidden" name="_method" value="PUT" />
    <label>Source: <a></a><input type="text" name="source" pattern="[a-zA-Z0-9]+" {has_err}/>@{domain}</a></label><br>
    <label>Target: <a><select name="user" {has_err}>{destination}</select></label><br>
    <input type="submit" value="Add Alias" {has_err} />
</form>"#)
    } else {
        String::new()
    };

    let delete = if permissions.admin() || permissions.delete_accounts(){
        r#"<input type="hidden" name="_method" value="DELETE" /><input type="submit" value="Delete Selected Aliases" />"#
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
<h2>Existing Aliases:</h2>
<p>Emails, that are sent to a Source-Email will be redirected to the Target-Email. Also the Target-Email can send as the Source-Email.</p>
<form method="POST">
{delete}
    <table>
        <tr>
            <th>Selected</th>
            <th>Source</th>
            <th>Target</th>
        </tr>
        {aliases}
    </table>
</form>
        "#).as_str())),
    }))
}
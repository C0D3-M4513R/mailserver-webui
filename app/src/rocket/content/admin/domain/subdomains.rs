use std::borrow::Cow;
use crate::rocket::content::admin::domain::{domain_linklist, template, unauth_error};
use crate::rocket::messages::{DATABASE_ERROR, LIST_SUBDOMAIN_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::Session;
use crate::SPECIAL_ROOT_DOMAIN_NAME;

#[rocket::get("/admin/<domain>/subdomains")]
pub async fn admin_domain_subdomains_get(session: Option<Session>, domain: &str) -> Return {
    admin_domain_subdomains_get_impl(session, domain, None).await
}

pub(in crate::rocket) async fn admin_domain_subdomains_get_impl(session: Option<Session>, domain: &str, error: Option<&str>) -> Return {
    let session = match session {
        None => return Return::Content((rocket::http::Status::Forbidden, TypedContent{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(unauth_error(domain)),
        })),
        Some(v) => v,
    };
    let no_perm = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, LIST_SUBDOMAIN_NO_PERM)),
    }));
    let permissions = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };

    if !permissions.admin() {
        if
        !permissions.view_domain() ||
            !permissions.list_subdomain()
        {
            return no_perm;
        }
    }

    let db = crate::get_db().await;
    let domains = match sqlx::query!(r#"
SELECT
    domains.id AS "id!",
    flattened_domains.name AS "name!"
FROM domains
    JOIN flattened_domains ON flattened_domains.id = domains.id
    JOIN flattened_web_domain_permissions permissions ON permissions.domain_id = domains.id AND permissions.user_id = $2
    JOIN flattened_web_domain_permissions parent_permissions ON parent_permissions.domain_id = $1 AND parent_permissions.user_id = $2
WHERE
     (
         permissions.is_owner OR permissions.view_domain OR permissions.admin OR
         permissions.super_owner OR parent_permissions.list_subdomain OR parent_permissions.admin
     ) AND
    $1 = domains.super AND domains.deleted = false"#, permissions.domain_id(), session.get_user_id())
        .fetch_all(&db)
        .await
    {
        Ok(v) => v.into_iter().filter_map(|v|{
            let id = v.id;
            let name = v.name;
            let modify = format!(r#"<a href="/admin/{name}">Modify</a>"#);
            Some(format!(r#"<tr><td><input class="domain-select" type="checkbox" name="domains[{id}]"/></td><td>{name}</td><td>{modify}</td></tr>"#))
        }).fold(String::new(), |a,b|format!("{a}{b}")),
        Err(err) => {

            log::error!("Error fetching accounts: {err}");
            return Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(template(domain, DATABASE_ERROR)),
            }));
        }
    };

    let deleted_domains = if permissions.admin() || permissions.list_deleted() {
        match sqlx::query!(r#"
SELECT
    domains.id AS "id!",
    domains.name AS "name!"
FROM flattened_domains domains
WHERE $1 = ANY(domains.super) AND domains.deleted = true"#, permissions.domain_id())
            .fetch_all(&db)
            .await
        {
            Ok(v) => {
                if v.is_empty() {
                    String::new()
                } else {
                    let deleted_domains = v.into_iter().filter_map(|v|{
                        let id = v.id;
                        let name = v.name;
                        if session.get_permissions().get(&name).map(|v|v.is_owner()||v.admin()|v.view_domain()).unwrap_or(false) {
                            return None;
                        }

                        Some(format!(r#"<tr><td><input class="domain-select" type="checkbox" name="domains[{id}]"/></td><td>{name}</td></tr>"#))
                    }).reduce(|a,b|format!("{a}{b}")).unwrap_or_default();
                    let delete = if permissions.admin() || permissions.delete_disabled() {
                        r#"<button type="submit" formaction="subdomains/delete">Permanently Delete Selected Domains</button>"#
                    } else { "" };
                    let undelete = if permissions.admin() || permissions.undelete() {
                        r#"<button type="submit" formaction="subdomains/recover">Recover Selected Domains</button>"#
                    } else { "" };
                    format!(r#"<h2>Disabled Subdomains</h2>
<form method="POST">{undelete}{delete}<table>
    <tr><th>Selected</th><th>Sub-Domain</th></tr>
    {deleted_domains}
</table></form>
                    "#)
                }
            },
            Err(err) => {

                log::error!("Error fetching deleted domains: {err}");
                const DISABLED_SUBDOMAINS_DB_ERROR:&str = const_format::concatcp!("<h2>Disabled Sub-Domains:</h2><p>", DATABASE_ERROR, "</p>");
                DISABLED_SUBDOMAINS_DB_ERROR.to_string()
            }
        }
    } else {
        String::new()
    };

    let new_subdomain = if permissions.admin() || permissions.create_subdomain() {
        let domain = if domain == SPECIAL_ROOT_DOMAIN_NAME { String::new() } else { format!(".{domain}") };
        format!(r#"<h2>Create new Subdomain:</h2>
<form method="POST">
    <input type="hidden" name="_method" value="PUT" />
    <label>Name: <a><input type="text" pattern="[a-zA-Z0-9]+" name="name" />{domain}</a></label>
    <input type="submit" value="Add Subdomain" />
</form>"#)
    } else {
        String::new()
    };

    let header = domain_linklist(&session, domain);
    let error = error.unwrap_or("");
    Return::Content((rocket::http::Status::Ok, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, format!(r#"
    {header}
<div id="subdomain-mod-error">{error}</div>
{new_subdomain}
<table><tr><td>
<h2>Existing Subdomains:</h2>
<form method="POST">
<input type="hidden" name="_method" value="DELETE" />
<input type="submit" value="Disable Selected Subdomains" />
    <table>
        <tr>
            <th></th>
            <th>Sub-Domain</th>
            <th>Actions</th>
        </tr>
        {domains}
    </table>
</form></td><td>{deleted_domains}</td></tr></table>
        "#).as_str())),
    }))
}
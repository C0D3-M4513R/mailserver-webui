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

    let db = crate::get_mysql().await;
    let domains = match sqlx::query!(r#"
SELECT
    domains.id AS "id!",
    domains.name AS "name!"
FROM virtual_domains domains
JOIN flattened_web_domain_permissions permissions ON permissions.domain_id = domains.id
WHERE
    ( $2 = ANY(domains.domain_owner)  OR permissions.view_domain OR permissions.admin) AND
    $1 = ANY(domains.super) AND permissions.user_id = $2"#, permissions.domain_id(), session.get_user_id())
        .fetch_all(db)
        .await
    {
        Ok(v) => v.into_iter().filter_map(|v|{
            let id = v.id;
            let name = v.name;
            let modify = format!(r#"<a href="/admin/{name}/view">Modify</a>"#);
            Some(format!(r#"<tr><td><input class="domain-select" type="checkbox" name="domains[{id}]"/></td><td>{name}</td><td>{modify}</td></tr>"#))
        }).fold(String::new(), |a,b|format!("{a}{b}")),
        Err(err) => {
            #[cfg(debug_assertions)]
            log::error!("Error fetching accounts: {err}");
            return Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(template(domain, DATABASE_ERROR)),
            }));
        }
    };

    let new_subdomain = if permissions.admin() || permissions.create_subdomain() {
        let domain = if domain == SPECIAL_ROOT_DOMAIN_NAME { String::new() } else { format!(".{domain}") };
        format!(r#"<h2>Create new Subdomain:</h2>
<form method="POST">
    <input type="hidden" name="_method" value="PUT" />
    <label>Name: <a><input type="text" name="name" />{domain}</a></label>
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
<h2>Existing Subdomains:</h2>
<form method="POST">
<input type="hidden" name="_method" value="DELETE" />
<input type="submit" value="Delete Selected Subdomains" />
    <table>
        <tr>
            <th></th>
            <th>Sub-Domain</th>
            <th>Actions</th>
        </tr>
        {domains}
    </table>
    </form>
        "#).as_str())),
    }))
}
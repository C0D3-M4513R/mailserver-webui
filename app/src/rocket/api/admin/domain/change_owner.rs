use std::borrow::Cow;
use rocket::http::CookieJar;
use crate::rocket::content::admin::domain::{template, unauth_error};
use crate::rocket::content::admin::domain::subdomains::admin_domain_subdomains_get_impl;
use crate::rocket::messages::{DATABASE_ERROR, OWNER_DOMAIN_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::{refresh_permission, Session};

mod private{
    #[derive(serde::Deserialize, serde::Serialize, rocket::form::FromForm)]
    pub struct ChangeOwner{
        pub owner: i64,
    }
}

#[rocket::put("/admin/<domain>/owner", data = "<data>")]
pub async fn admin_domain_owner_put(session: Option<Session>, domain: &'_ str, data: rocket::form::Form<private::ChangeOwner>, cookie_jar: &'_ CookieJar<'_>) -> Return {
    let unauth_error = Return::Content((rocket::http::Status::Unauthorized, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(unauth_error(domain)),
    }));
    let mut session = match session {
        None => return unauth_error,
        Some(v) => v,
    };
    let pool = crate::get_mysql().await;
    refresh_permission!(session, cookie_jar, domain, pool);

    let no_perm = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, OWNER_DOMAIN_NO_PERM)),
    }));
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permission.is_owner() {
        return no_perm;
    }

    match sqlx::query!(r#"
UPDATE domains
SET domain_owner = $1
FROM virtual_users users, flattened_domains, flattened_web_domain_permissions slf_perms
WHERE
    users.id = $1 AND slf_perms.user_id = $2 AND domains.id = $3 AND
    flattened_domains.id = domains.id AND slf_perms.domain_id = domains.id AND
    (slf_perms.user_id = ANY(flattened_domains.domain_owner) OR slf_perms.admin OR slf_perms.list_accounts)
"#, data.owner, session.get_user_id(), permission.domain_id()).execute(pool).await {
        Ok(v) => {
            if v.rows_affected() != 1 {
                log::debug!("Tried to update domain owner, but no rows were changed?");
            }
        },
        Err(err) => {
            log::error!("Error creating subdomain: {err}");
            let mut result =  admin_domain_subdomains_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
            result.override_status(rocket::http::Status::InternalServerError);
            return result;
        }
    };

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}")))
}
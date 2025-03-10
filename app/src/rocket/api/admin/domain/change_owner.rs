use std::borrow::Cow;
use rocket::http::CookieJar;
use crate::rocket::content::admin::domain::{template, unauth_error};
use crate::rocket::content::admin::domain::subdomains::admin_domain_subdomains_get_impl;
use crate::rocket::messages::{DATABASE_ERROR, GET_PERMISSION_ERROR, OWNER_DOMAIN_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::Session;

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
    match session.refresh_permissions(cookie_jar).await {
        Ok(()) => {},
        Err(err) => {
            log::error!("Error refreshing permissions: {err}");
            return Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(template(domain, GET_PERMISSION_ERROR)),
            }));
        }
    }

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

    let db = crate::get_mysql().await;
    match sqlx::query!(r#"
UPDATE domains
SET domain_owner = $1
FROM users, flattened_domains
WHERE
    domains.id = $3 AND
    flattened_domains.id = $1 AND $2 = ANY(flattened_domains.domain_owner) AND
    users.id = $1 AND users.deleted = false
"#, data.owner, session.get_user_id(), permission.domain_id()).execute(db).await {
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

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/view")))
}
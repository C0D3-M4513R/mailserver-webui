use std::borrow::Cow;
use rocket::http::CookieJar;
use crate::rocket::auth::permissions::UpdatePermissions;
use crate::rocket::content::admin::domain::{template, unauth_error};
use crate::rocket::content::admin::domain::permissions::admin_domain_permissions_get_impl;
use crate::rocket::content::admin::domain::subdomains::admin_domain_subdomains_get_impl;
use crate::rocket::messages::{DATABASE_ERROR, GET_PERMISSION_ERROR, MANAGE_PERMISSION_NO_PERM, MODIFY_DOMAIN_NO_PERM, SUBDOMAIN_INVALID_CHARS};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::{refresh_permission, Session};
mod private{
    #[derive(rocket::form::FromForm)]
    pub struct RenameSubdomain<'a>{
        pub name: &'a str,
    }
    #[derive(rocket::form::FromForm)]
    pub struct AcceptsEmail{
        pub accepts_email: bool,
    }
}

#[rocket::put("/admin/<domain>/name", data = "<data>")]
pub async fn admin_domain_name_put(session: Option<Session>, domain: &'_ str, data: rocket::form::Form<private::RenameSubdomain<'_>>, cookie_jar: &'_ CookieJar<'_>) -> Return {
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
        content: Cow::Owned(template(domain, MODIFY_DOMAIN_NO_PERM)),
    }));
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permission.admin() && !permission.modify_domain() {
        return no_perm;
    }
    if !data.name.is_ascii() {
        return Return::Content((rocket::http::Status::Forbidden, TypedContent{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(template(domain, SUBDOMAIN_INVALID_CHARS)),
        }));
    }

    match sqlx::query!("UPDATE domains SET name = $1 WHERE id = $2 AND domains.id != domains.super", data.name, permission.domain_id()).execute(pool).await {
        Ok(v) => {
            if v.rows_affected() == 1 {
                refresh_permission!(session, cookie_jar, domain, pool);
            } else {
                log::warn!("Rust vs DB Permission Check Inconsistency: Wanted to update domain name from {domain} to {}, but no rows were changed.", data.name);
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
#[rocket::put("/admin/<domain>/accepts_email", data = "<data>")]
#[allow(non_snake_case)]
pub async fn admin_domain__accepts_email__put(session: Option<Session>, domain: &'_ str, data: rocket::form::Form<private::AcceptsEmail>, cookie_jar: &'_ CookieJar<'_>) -> Return {
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
        content: Cow::Owned(template(domain, MODIFY_DOMAIN_NO_PERM)),
    }));
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permission.admin() && !permission.modify_domain() {
        return no_perm;
    }

    match sqlx::query!("UPDATE domains SET accepts_email = $1 WHERE deleted = false AND id = $2", data.accepts_email, permission.domain_id()).execute(pool).await {
        Ok(v) => {
            if v.rows_affected() == 1 {
                refresh_permission!(session, cookie_jar, domain, pool);
            } else {
                log::warn!("Rust vs DB Permission Check Inconsistency: Wanted to update accepts_email on domain {domain}, but no rows were changed.");
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


#[rocket::put("/admin/<domain>/permissions", data = "<data>")]
pub async fn admin_domain_permissions_put(
    session: Option<Session>,
    domain: &'_ str,
    data: rocket::form::Form<UpdatePermissions>,
    cookie_jar: &'_ CookieJar<'_>
) -> Return {
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
        content: Cow::Owned(template(domain, MANAGE_PERMISSION_NO_PERM)),
    }));
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permission.admin() && !permission.manage_permissions() {
        return no_perm;
    }

    match data.apply_perms(session.get_user_id(), permission.domain_id(), pool).await {
        Ok(_) => {  },
        Err(err) => {
            log::error!("Error applying account permissions: {err}");
            let mut err = admin_domain_permissions_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
            err.override_status(rocket::http::Status::InternalServerError);
            return err;
        }
    };

    if data.users.contains_key(&session.get_user_id()) && !permission.is_owner() {
        match session.refresh_permissions(pool, cookie_jar).await {
            Ok(()) => {},
            Err(err) => {
                log::error!("Error refreshing permissions: {err}");
                return Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                    content_type: rocket::http::ContentType::HTML,
                    content: Cow::Owned(template(domain, GET_PERMISSION_ERROR)),
                }));
            }
        }
    }

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/permissions")))
}
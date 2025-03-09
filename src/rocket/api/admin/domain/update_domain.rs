use std::borrow::Cow;
use rocket::http::CookieJar;
use crate::rocket::content::admin::domain::{template, unauth_error};
use crate::rocket::content::admin::domain::subdomains::admin_domain_subdomains_get_impl;
use crate::rocket::messages::{DATABASE_ERROR, GET_PERMISSION_ERROR, MODIFY_DOMAIN_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::session::Session;

mod private{
    #[derive(serde::Deserialize, serde::Serialize, rocket::form::FromForm)]
    pub struct RenameSubdomain<'a>{
        pub name: &'a str,
    }
    #[derive(serde::Deserialize, serde::Serialize, rocket::form::FromForm)]
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
        content: Cow::Owned(template(domain, MODIFY_DOMAIN_NO_PERM)),
    }));
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permission.get_admin() && !permission.get_modify_domain() {
        return no_perm;
    }

    let db = crate::get_mysql().await;
    match sqlx::query!("UPDATE domains SET name = $1 WHERE id = $2 AND domains.id != domains.super", data.name, permission.get_domain_id()).execute(db).await {
        Ok(_) => {},
        Err(err) => {
            log::error!("Error creating subdomain: {err}");
            let mut result =  admin_domain_subdomains_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
            result.override_status(rocket::http::Status::InternalServerError);
            return result;
        }
    };

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/view")))
}
#[rocket::put("/admin/<domain>/accepts_email", data = "<data>")]
pub async fn admin_domain__accepts_email__put(session: Option<Session>, domain: &'_ str, data: rocket::form::Form<private::AcceptsEmail>, cookie_jar: &'_ CookieJar<'_>) -> Return {
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
        content: Cow::Owned(template(domain, MODIFY_DOMAIN_NO_PERM)),
    }));
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permission.get_admin() && !permission.get_modify_domain() {
        return no_perm;
    }

    let db = crate::get_mysql().await;
    match sqlx::query!("UPDATE domains SET accepts_email = $1 WHERE deleted = false AND id = $2", data.accepts_email, permission.get_domain_id()).execute(db).await {
        Ok(_) => {},
        Err(err) => {
            log::error!("Error creating subdomain: {err}");
            let mut result =  admin_domain_subdomains_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
            result.override_status(rocket::http::Status::InternalServerError);
            return result;
        }
    };

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/view")))
}
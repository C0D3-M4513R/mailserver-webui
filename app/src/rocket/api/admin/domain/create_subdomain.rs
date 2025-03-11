use std::borrow::Cow;
use rocket::http::CookieJar;
use crate::rocket::content::admin::domain::{template, unauth_error};
use crate::rocket::content::admin::domain::subdomains::admin_domain_subdomains_get_impl;
use crate::rocket::messages::{SUBDOMAIN_INVALID_CHARS, CREATE_SUBDOMAIN_NO_PERM, DATABASE_ERROR};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::{refresh_permission, Session};

mod private{
    #[derive(serde::Deserialize, serde::Serialize, rocket::form::FromForm)]
    pub struct CreateSubdomain<'a>{
        pub name: &'a str,
    }
}

#[rocket::put("/admin/<domain>/subdomains", data = "<data>")]
pub async fn admin_domain_subdomains_put(session: Option<Session>, domain: &'_ str, data: rocket::form::Form<private::CreateSubdomain<'_>>, cookie_jar: &'_ CookieJar<'_>) -> Return {
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
        content: Cow::Owned(template(domain, CREATE_SUBDOMAIN_NO_PERM)),
    }));
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permission.admin() && !permission.create_subdomain() {
        return no_perm;
    }
    if !data.name.is_ascii() {
        return Return::Content((rocket::http::Status::Forbidden, TypedContent{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(template(domain, SUBDOMAIN_INVALID_CHARS)),
        }));
    }

    match sqlx::query!("INSERT INTO domains (name, super, domain_owner) VALUES ($1, $2, $3)", data.name, permission.domain_id(), session.get_user_id())
        .execute(pool).await {
        Ok(_) => {},
        Err(err) => {
            log::error!("Error creating subdomain: {err}");
            let mut result =  admin_domain_subdomains_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
            result.override_status(rocket::http::Status::InternalServerError);
            return result;
        }
    };
    refresh_permission!(session, cookie_jar, domain, pool);

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/subdomains")))
}
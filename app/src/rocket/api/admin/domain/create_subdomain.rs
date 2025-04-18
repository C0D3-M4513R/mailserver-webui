use std::borrow::Cow;
use crate::rocket::content::admin::domain::{template, unauth_error};
use crate::rocket::content::admin::domain::subdomains::admin_domain_subdomains_get_impl;
use crate::rocket::messages::{SUBDOMAIN_INVALID_CHARS, CREATE_SUBDOMAIN_NO_PERM, DATABASE_ERROR, DATABASE_PERMISSION_ERROR};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::Session;

mod private{
    #[derive(serde::Deserialize, serde::Serialize, rocket::form::FromForm)]
    pub struct CreateSubdomain<'a>{
        pub name: &'a str,
    }
}

#[rocket::put("/admin/<domain>/subdomains", data = "<data>")]
pub async fn admin_domain_subdomains_put(
    session: Option<Session>,
    domain: &'_ str,
    data: rocket::form::Form<private::CreateSubdomain<'_>>,
) -> Return {
    let unauth_error = Return::Content((rocket::http::Status::Unauthorized, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(unauth_error(domain)),
    }));
    let session = match session {
        None => return unauth_error,
        Some(v) => v,
    };
    let pool = crate::get_db().await;

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

    match sqlx::query!("SELECT insert_subdomain($1::bigint, $2::text, $3::bigint) as id",
        permission.domain_id(), data.name, session.get_user_id()
    ).fetch_optional(&pool).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(None) => return Return::Content((rocket::http::Status::Forbidden, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(template(domain, DATABASE_PERMISSION_ERROR)),
            })),
        Ok(Some(_)) => {},
        Err(err) => {
            log::error!("Error creating subdomain: {err}");
            let mut result =  admin_domain_subdomains_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
            result.override_status(rocket::http::Status::InternalServerError);
            return result;
        }
    };
    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/subdomains")))
}
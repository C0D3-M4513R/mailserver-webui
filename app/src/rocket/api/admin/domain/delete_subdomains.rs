use std::borrow::Cow;
use crate::rocket::content::admin::domain::{template, unauth_error};
use crate::rocket::messages::{DATABASE_ERROR, GET_PERMISSION_ERROR, DELETE_SUBDOMAIN_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::Session;

mod private {
    use std::collections::HashMap;

    #[derive(Debug, rocket::form::FromForm)]
    pub struct DeleteSubdomains{
        pub domains: HashMap<i64, bool>,
    }
}

#[rocket::delete("/admin/<domain>/subdomains", data="<data>")]
pub async fn admin_domain_subdomains_delete(
    session: Option<Session>,
    domain: &str,
    data: ::rocket::form::Form<private::DeleteSubdomains>,
    cookie_jar: &'_ rocket::http::CookieJar<'_>,
) -> Return {
    let unauth = Return::Content((rocket::http::Status::Unauthorized, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(unauth_error(domain)),
    }));
    let mut session = match session {
        None => return unauth,
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
        content: Cow::Owned(template(domain, DELETE_SUBDOMAIN_NO_PERM)),
    }));
    let permissions = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permissions.admin() && !permissions.delete_subdomain(){
        return no_perm;
    }

    let db_error = Return::Content((rocket::http::Status::InternalServerError, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, DATABASE_ERROR)),
    }));

    let db = crate::get_mysql().await;
    let domains = data.into_inner().domains.into_iter().filter_map(|(k, v)|if v {Some(k)} else {None}).collect::<Vec<_>>();
    match sqlx::query!(r#"
DELETE FROM virtual_domains domains WHERE domains.id = ANY($1)
        "#,
        &domains,
    ).execute(db).await {
        Ok(_) => Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/subdomains"))),
        Err(err) => {
            log::error!("Error deleting subdomain: {err}");
            db_error
        }
    }

}
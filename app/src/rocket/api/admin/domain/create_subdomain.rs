use crate::rocket::response::Return;
use crate::rocket::content::admin::domain::UNAUTH;
use crate::rocket::content::admin::domain::subdomains::admin_domain_subdomains_get_impl;
use crate::rocket::messages::{SUBDOMAIN_INVALID_CHARS, CREATE_SUBDOMAIN_NO_PERM, DATABASE_ERROR, DATABASE_PERMISSION_ERROR};
use crate::rocket::auth::session::Session;
use crate::rocket::template::authenticated::domain_base::DomainBase;

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
    let session = match session {
        None => return UNAUTH(domain).into(),
        Some(v) => v,
    };
    let pool = crate::get_db().await;

    let no_perm = (rocket::http::Status::Forbidden, DomainBase{
        domain,
        content: CREATE_SUBDOMAIN_NO_PERM,
    });
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm.into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.create_subdomain() {
        return no_perm.into();
    }
    if !data.name.is_ascii() {
        return (rocket::http::Status::Forbidden, DomainBase{
            domain,
            content: SUBDOMAIN_INVALID_CHARS,
        }).into();
    }

    match sqlx::query!("SELECT insert_subdomain($1::bigint, $2::text, $3::bigint) as id",
        permission.domain_id(), data.name, session.get_user_id()
    ).fetch_optional(&pool).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(None) => return (rocket::http::Status::Forbidden, DomainBase{
            domain,
            content: DATABASE_PERMISSION_ERROR,
        }).into(),
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
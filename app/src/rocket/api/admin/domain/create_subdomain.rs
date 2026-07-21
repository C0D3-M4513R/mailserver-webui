use crate::rocket::response::Return;
use crate::rocket::content::admin::domain::unauth;
use crate::rocket::content::admin::domain::subdomains::admin_domain_subdomains_get_impl;
use crate::rocket::messages::{SUBDOMAIN_INVALID_CHARS, CREATE_SUBDOMAIN_NO_PERM, DATABASE_ERROR, DATABASE_PERMISSION_ERROR};
use crate::rocket::auth::session::Session;
use crate::rocket::template::authenticated::domain_base::DomainBase;

mod private{
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct CreateSubdomain{
        pub name: String,
    }
}

#[actix_web::post("/admin/<domain>/subdomains/create")]
pub async fn admin_domain_subdomains_put(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    data: actix_web::web::Form<private::CreateSubdomain>,
) -> Return {
    let session = match &*session_ref {
        None => return unauth(domain).into(),
        Some(v) => v,
    };
    let pool = crate::get_db().await;

    let no_perm = |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: CREATE_SUBDOMAIN_NO_PERM,
    });
    let permission = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.create_subdomain() {
        return no_perm(domain.into()).into();
    }
    if !data.name.is_ascii() {
        return (actix_web::http::StatusCode::FORBIDDEN, DomainBase{
            domain: domain.into(),
            content: SUBDOMAIN_INVALID_CHARS,
        }).into();
    }

    match sqlx::query!("SELECT insert_subdomain($1::bigint, $2::text, $3::bigint) as id",
        permission.domain_id(), data.name, session.get_user_id()
    ).fetch_optional(&pool).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(None) => return (actix_web::http::StatusCode::FORBIDDEN, DomainBase{
            domain: domain.into(),
            content: DATABASE_PERMISSION_ERROR,
        }).into(),
        Ok(Some(_)) => {},
        Err(err) => {
            log::error!("Error creating subdomain: {err}");
            return admin_domain_subdomains_get_impl(&*session_ref, domain, Some(DATABASE_ERROR))
                .await
                .override_status(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    Return::redirect_to(format!("/admin/{domain}/subdomains"))
}
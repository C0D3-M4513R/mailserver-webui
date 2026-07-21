use crate::rocket::auth::permissions::UpdatePermissions;
use crate::rocket::content::admin::domain::unauth;
use crate::rocket::content::admin::domain::permissions::admin_domain_permissions_get_impl;
use crate::rocket::content::admin::domain::subdomains::admin_domain_subdomains_get_impl;
use crate::rocket::messages::{DATABASE_ERROR, DATABASE_PERMISSION_ERROR, MANAGE_PERMISSION_NO_PERM, MODIFY_DOMAIN_NO_PERM, SUBDOMAIN_INVALID_CHARS};
use crate::rocket::response::Return;
use crate::rocket::auth::session::Session;
use crate::rocket::template::authenticated::domain_base::DomainBase;

mod private{
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct RenameSubdomain{
        pub name: String,
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct AcceptsEmail{
        pub accepts_email: bool,
    }
}

#[actix_web::post("/admin/<domain>/name")]
pub async fn admin_domain_name_put(session_ref: actix_web::web::ReqData<Option<Session>>, domain: String, data: actix_web::web::Form<private::RenameSubdomain>) -> Return {
    let session = match &*session_ref {
        None => return unauth(domain).into(),
        Some(v) => v,
    };

    let no_perm = |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: MODIFY_DOMAIN_NO_PERM,
    });
    let permission = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.modify_domain() {
        return no_perm(domain.into()).into();
    }
    if !data.name.is_ascii() {
        return (actix_web::http::StatusCode::FORBIDDEN, DomainBase{
            domain: domain.into(),
            content: SUBDOMAIN_INVALID_CHARS,
        }).into();
    }

    let pool = crate::get_db().await;
    match sqlx::query!("SELECT change_domain_name($1, $2, $3) as id", permission.domain_id(), data.name, session.get_user_id())
    .fetch_optional(&pool).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(Some(_)) => {},
        Ok(None) => return (actix_web::http::StatusCode::FORBIDDEN, DomainBase{
                domain: domain.into(),
                content: DATABASE_PERMISSION_ERROR,
            }).into(),
        Err(err) => {
            log::error!("Error changing domain name: {err}");
            return admin_domain_subdomains_get_impl(&*session_ref, domain, Some(DATABASE_ERROR))
                .await
                .override_status(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    Return::redirect_to_value(actix_web::http::header::HeaderValue::from_static("/admin"))
}
#[actix_web::post("/admin/<domain>/accepts_email")]
#[allow(non_snake_case)]
pub async fn admin_domain__accepts_email__put(session_ref: actix_web::web::ReqData<Option<Session>>, domain: String, data: actix_web::web::Form<private::AcceptsEmail>) -> Return {
    let session = match &*session_ref {
        None => return unauth(domain).into(),
        Some(v) => v,
    };
    let pool = crate::get_db().await;

    let no_perm = |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: MODIFY_DOMAIN_NO_PERM,
    });
    let permission = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.modify_domain() {
        return no_perm(domain.into()).into();
    }

    match sqlx::query!("SELECT change_domain_accepts_email($1, $2, $3) as id", permission.domain_id(), data.accepts_email, session.get_user_id())
        .fetch_optional(&pool).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(Some(_)) => {},
        Ok(None) => return (actix_web::http::StatusCode::FORBIDDEN, DomainBase{
                domain: domain.into(),
                content: DATABASE_PERMISSION_ERROR,
            }).into(),
        Err(err) => {
            log::error!("Error changing domain name: {err}");
            return admin_domain_subdomains_get_impl(&*session_ref, domain, Some(DATABASE_ERROR))
                .await
                .override_status(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    Return::redirect_to(format!("/admin/{domain}"))
}


#[actix_web::post("/admin/<domain>/permissions")]
pub async fn admin_domain_permissions_put(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    data: actix_web::web::Form<UpdatePermissions>
) -> Return {
    let session = match &*session_ref {
        None => return unauth(domain).into(),
        Some(v) => v,
    };

    let no_perm = |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: MANAGE_PERMISSION_NO_PERM,
    });
    let permission = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.manage_permissions() {
        return no_perm(domain.into()).into();
    }

    let pool = crate::get_db().await;
    match data.apply_perms(session.get_user_id(), permission.domain_id(), pool).await {
        Ok(_) => {  },
        Err(err) => {
            log::error!("Error applying account permissions: {err}");
            return admin_domain_permissions_get_impl(&*session_ref, domain, Some(DATABASE_ERROR))
                .await
                .override_status(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    Return::redirect_to(format!("/admin/{domain}/permissions"))
}
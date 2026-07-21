use crate::rocket::content::admin::domain::unauth;
use crate::rocket::content::admin::domain::subdomains::admin_domain_subdomains_get_impl;
use crate::rocket::messages::{DATABASE_ERROR, DATABASE_PERMISSION_ERROR, OWNER_DOMAIN_NO_PERM};
use crate::rocket::response::Return;
use crate::rocket::auth::session::Session;
use crate::rocket::template::authenticated::domain_base::DomainBase;

mod private{
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct ChangeOwner{
        pub owner: i64,
    }
}

#[actix_web::post("/admin/<domain>/owner")]
pub async fn admin_domain_owner_put(session_ref: actix_web::web::ReqData<Option<Session>>, domain: String, data: actix_web::web::Form<private::ChangeOwner>) -> Return {
    let session = match &*session_ref {
        None => return unauth(domain).into(),
        Some(v) => v,
    };
    let no_perm = |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: OWNER_DOMAIN_NO_PERM,
    });
    let permission = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permission.is_owner() {
        return no_perm(domain.into()).into();
    }

    let pool = crate::get_db().await;

    match sqlx::query!(r#"SELECT change_domain_owner($1, $2, $3) as id;"#, permission.domain_id(), data.owner, session.get_user_id())
        .fetch_optional(&pool).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(Some(_)) => {},
        Ok(None) => return (actix_web::http::StatusCode::FORBIDDEN, DomainBase{
            domain: domain.into(),
            content: DATABASE_PERMISSION_ERROR,
        }).into(),
        Err(err) => {
            log::error!("Error creating subdomain: {err}");
            return admin_domain_subdomains_get_impl(&*session_ref, domain, Some(DATABASE_ERROR))
                .await
                .override_status(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR)
            ;
        }
    };

    Return::redirect_to(format!("/admin/{domain}"))
}
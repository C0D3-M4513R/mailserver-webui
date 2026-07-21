use crate::rocket::content::admin::domain::unauth;
use crate::rocket::messages::{ALIAS_INVALID_CHARS, CREATE_ALIAS_NO_PERM, DATABASE_ERROR, DATABASE_PERMISSION_ERROR};
use crate::rocket::response::Return;
use crate::rocket::auth::session::Session;
use crate::rocket::content::admin::domain::aliases::admin_domain_aliases_get_impl;
use crate::rocket::template::authenticated::domain_base::DomainBase;

mod private{
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct CreateAlias{
        pub source: String,
        pub user: i64,
    }
}

#[actix_web::post("/admin/<domain>/aliases/create")]
pub async fn admin_domain_aliases_put(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    data: actix_web::web::Form<private::CreateAlias>
) -> Return {
    let session = match &*session_ref {
        None => return unauth(domain).into(),
        Some(v) => v,
    };

    if !data.source.is_ascii() {
        return (actix_web::http::StatusCode::BAD_REQUEST, DomainBase{
            domain: domain.into(),
            content: ALIAS_INVALID_CHARS,
        }).into();
    }

    let pool = crate::get_db().await;

    let no_perm = |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: CREATE_ALIAS_NO_PERM,
    });
    let permission = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.create_alias() {
        return no_perm(domain.into()).into();
    }

    match sqlx::query!("
SELECT insert_new_alias($1, $2, $3, $4) as id", permission.domain_id(), data.source,  data.user, session.get_user_id())
    .fetch_optional(&pool).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(Some(_)) => {},
        Ok(None) => return (actix_web::http::StatusCode::FORBIDDEN, DomainBase{
            domain: domain.into(),
            content: DATABASE_PERMISSION_ERROR,
        }).into(),
        Err(err) => {
            log::error!("Error creating account: {err}");
            return admin_domain_aliases_get_impl(&*session_ref, domain, Some(DATABASE_ERROR))
                .await
                .override_status(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    Return::redirect_to(format!("/admin/{domain}/aliases"))
}
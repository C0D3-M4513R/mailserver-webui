use crate::rocket::content::admin::domain::UNAUTH;
use crate::rocket::messages::{ALIAS_INVALID_CHARS, CREATE_ALIAS_NO_PERM, DATABASE_ERROR, DATABASE_PERMISSION_ERROR};
use crate::rocket::response::Return;
use crate::rocket::auth::session::Session;
use crate::rocket::content::admin::domain::aliases::admin_domain_aliases_get_impl;
use crate::rocket::template::authenticated::domain_base::DomainBase;

mod private{
    #[derive(serde::Deserialize, serde::Serialize, rocket::form::FromForm)]
    pub struct CreateAlias<'a>{
        pub source: &'a str,
        pub user: i64,
    }
}

#[rocket::put("/admin/<domain>/aliases", data = "<data>")]
pub async fn admin_domain_aliases_put(
    session: Option<Session>,
    domain: &'_ str,
    data: rocket::form::Form<private::CreateAlias<'_>>
) -> Return {
    let session = match session {
        None => return UNAUTH(domain).into(),
        Some(v) => v,
    };

    if !data.source.is_ascii() {
        return (rocket::http::Status::BadRequest, DomainBase{
            domain,
            content: ALIAS_INVALID_CHARS,
        }).into();
    }

    let pool = crate::get_db().await;

    let no_perm = (rocket::http::Status::Forbidden, DomainBase{
        domain,
        content: CREATE_ALIAS_NO_PERM,
    });
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm.into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.create_alias() {
        return no_perm.into();
    }

    match sqlx::query!("
SELECT insert_new_alias($1, $2, $3, $4) as id", permission.domain_id(), data.source,  data.user, session.get_user_id())
    .fetch_optional(&pool).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(Some(_)) => {},
        Ok(None) => return (rocket::http::Status::Forbidden, DomainBase{
            domain,
            content: DATABASE_PERMISSION_ERROR,
        }).into(),
        Err(err) => {
            log::error!("Error creating account: {err}");
            let mut result = admin_domain_aliases_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
            result.override_status(rocket::http::Status::InternalServerError);
            return result;
        }
    };

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/aliases")))
}
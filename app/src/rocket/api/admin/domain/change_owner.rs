use std::borrow::Cow;
use crate::rocket::content::admin::domain::{template, UNAUTH};
use crate::rocket::content::admin::domain::subdomains::admin_domain_subdomains_get_impl;
use crate::rocket::messages::{DATABASE_ERROR, DATABASE_PERMISSION_ERROR, OWNER_DOMAIN_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::Session;
use crate::rocket::template::authenticated::domain_base::DomainBase;

mod private{
    #[derive(serde::Deserialize, serde::Serialize, rocket::form::FromForm)]
    pub struct ChangeOwner{
        pub owner: i64,
    }
}

#[rocket::put("/admin/<domain>/owner", data = "<data>")]
pub async fn admin_domain_owner_put(session: Option<Session>, domain: &'_ str, data: rocket::form::Form<private::ChangeOwner>) -> Return {
    let session = match session {
        None => return UNAUTH(domain).into(),
        Some(v) => v,
    };
    let no_perm = (rocket::http::Status::Forbidden, DomainBase{
        domain,
        content: OWNER_DOMAIN_NO_PERM,
    });
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm.into(),
        Some(v) => v,
    };
    if !permission.is_owner() {
        return no_perm.into();
    }

    let pool = crate::get_db().await;

    match sqlx::query!(r#"SELECT change_domain_owner($1, $2, $3) as id;"#, permission.domain_id(), data.owner, session.get_user_id())
        .fetch_optional(&pool).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(Some(_)) => {},
        Ok(None) => return Return::Content((rocket::http::Status::Forbidden, TypedContent{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(template(domain, DATABASE_PERMISSION_ERROR)),
        })),
        Err(err) => {
            log::error!("Error creating subdomain: {err}");
            let mut result =  admin_domain_subdomains_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
            result.override_status(rocket::http::Status::InternalServerError);
            return result;
        }
    };

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}")))
}
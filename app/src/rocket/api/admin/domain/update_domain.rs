use crate::rocket::auth::permissions::UpdatePermissions;
use crate::rocket::content::admin::domain::UNAUTH;
use crate::rocket::content::admin::domain::permissions::admin_domain_permissions_get_impl;
use crate::rocket::content::admin::domain::subdomains::admin_domain_subdomains_get_impl;
use crate::rocket::messages::{DATABASE_ERROR, DATABASE_PERMISSION_ERROR, MANAGE_PERMISSION_NO_PERM, MODIFY_DOMAIN_NO_PERM, SUBDOMAIN_INVALID_CHARS};
use crate::rocket::response::Return;
use crate::rocket::auth::session::Session;
use crate::rocket::template::authenticated::domain_base::DomainBase;

mod private{
    #[derive(rocket::form::FromForm)]
    pub struct RenameSubdomain<'a>{
        pub name: &'a str,
    }
    #[derive(rocket::form::FromForm)]
    pub struct AcceptsEmail{
        pub accepts_email: bool,
    }
}

#[rocket::put("/admin/<domain>/name", data = "<data>")]
pub async fn admin_domain_name_put(session: Option<Session>, domain: &'_ str, data: rocket::form::Form<private::RenameSubdomain<'_>>) -> Return {
    let session = match session {
        None => return UNAUTH(domain).into(),
        Some(v) => v,
    };

    let no_perm = (rocket::http::Status::Forbidden, DomainBase{
        domain,
        content: MODIFY_DOMAIN_NO_PERM,
    });
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm.into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.modify_domain() {
        return no_perm.into();
    }
    if !data.name.is_ascii() {
        return (rocket::http::Status::Forbidden, DomainBase{
            domain,
            content: SUBDOMAIN_INVALID_CHARS,
        }).into();
    }

    let pool = crate::get_db().await;
    match sqlx::query!("SELECT change_domain_name($1, $2, $3) as id", permission.domain_id(), data.name, session.get_user_id())
    .fetch_optional(&pool).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(Some(_)) => {},
        Ok(None) => return (rocket::http::Status::Forbidden, DomainBase{
                domain,
                content: DATABASE_PERMISSION_ERROR,
            }).into(),
        Err(err) => {
            log::error!("Error changing domain name: {err}");
            let mut result =  admin_domain_subdomains_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
            result.override_status(rocket::http::Status::InternalServerError);
            return result;
        }
    };

    Return::Redirect(rocket::response::Redirect::to(rocket::uri!("/admin")))
}
#[rocket::put("/admin/<domain>/accepts_email", data = "<data>")]
#[allow(non_snake_case)]
pub async fn admin_domain__accepts_email__put(session: Option<Session>, domain: &'_ str, data: rocket::form::Form<private::AcceptsEmail>) -> Return {
    let session = match session {
        None => return UNAUTH(domain).into(),
        Some(v) => v,
    };
    let pool = crate::get_db().await;

    let no_perm = (rocket::http::Status::Forbidden, DomainBase{
        domain,
        content: MODIFY_DOMAIN_NO_PERM,
    });
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm.into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.modify_domain() {
        return no_perm.into();
    }

    match sqlx::query!("SELECT change_domain_accepts_email($1, $2, $3) as id", permission.domain_id(), data.accepts_email, session.get_user_id())
        .fetch_optional(&pool).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(Some(_)) => {},
        Ok(None) => return (rocket::http::Status::Forbidden, DomainBase{
                domain,
                content: DATABASE_PERMISSION_ERROR,
            }).into(),
        Err(err) => {
            log::error!("Error changing domain name: {err}");
            let mut result =  admin_domain_subdomains_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
            result.override_status(rocket::http::Status::InternalServerError);
            return result;
        }
    };

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}")))
}


#[rocket::put("/admin/<domain>/permissions", data = "<data>")]
pub async fn admin_domain_permissions_put(
    session: Option<Session>,
    domain: &'_ str,
    data: rocket::form::Form<UpdatePermissions>
) -> Return {
    let session = match session {
        None => return UNAUTH(domain).into(),
        Some(v) => v,
    };

    let no_perm = (rocket::http::Status::Forbidden, DomainBase{
        domain,
        content: MANAGE_PERMISSION_NO_PERM,
    });
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm.into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.manage_permissions() {
        return no_perm.into();
    }

    let pool = crate::get_db().await;
    match data.apply_perms(session.get_user_id(), permission.domain_id(), pool).await {
        Ok(_) => {  },
        Err(err) => {
            log::error!("Error applying account permissions: {err}");
            let mut err = admin_domain_permissions_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
            err.override_status(rocket::http::Status::InternalServerError);
            return err;
        }
    };

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/permissions")))
}
use crate::rocket::response::Return;
use crate::rocket::auth::check_password::set_password;
use crate::rocket::content::admin::domain::UNAUTH;
use crate::rocket::content::admin::domain::account::admin_domain_account_get_impl;
use crate::rocket::messages::{ACCOUNT_INVALID_CHARS, DATABASE_ERROR, DATABASE_PERMISSION_ERROR, MANAGE_PERMISSION_NO_PERM, MODIFY_ACCOUNT_NO_PERM};
use crate::rocket::auth::session::Session;
use crate::rocket::auth::permissions::{UpdatePermissions};
use crate::rocket::template::authenticated::domain_base::DomainBase;

pub(super) mod private{
    #[derive(rocket::form::FromForm)]
    pub struct UpdateAccountEmail<'a>{
        pub email: &'a str,
    }
    #[derive(rocket::form::FromForm)]
    pub struct UpdateAccountPassword{
        pub password: String,
    }
    #[derive(rocket::form::FromForm)]
    pub struct UpdateUserPermissions{
        pub self_change_password: bool,
    }
}

#[rocket::put("/admin/<domain>/accounts/<user_name>/email", data = "<data>")]
pub async fn admin_domain_account_email_put(
    session: Option<Session>,
    domain: &'_ str,
    user_name: &'_ str,
    data: rocket::form::Form<private::UpdateAccountEmail<'_>>
) -> Return {
    let session = match session {
        None => return UNAUTH(domain).into(),
        Some(v) => v,
    };

    if !data.email.is_ascii() {
        return (rocket::http::Status::BadRequest, DomainBase{
            domain,
            content: ACCOUNT_INVALID_CHARS,
        }).into();
    }
    let pool = crate::get_db().await;

    let no_perm = (rocket::http::Status::Forbidden, DomainBase{
        domain,
        content: MODIFY_ACCOUNT_NO_PERM,
    });
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm.into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.modify_accounts() {
        return no_perm.into();
    }

    match sqlx::query!("SELECT set_user_email(users.id, $1, $2) as id from users WHERE email = $3 AND domain_id = $4",
        data.email, session.get_user_id(), user_name, permission.domain_id())
        .fetch_optional(&pool).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(Some(_)) => {},
        Ok(None) => return (rocket::http::Status::Forbidden, DomainBase{
            domain,
            content: DATABASE_PERMISSION_ERROR,
        }).into(),
        Err(err) => {
            log::error!("Error updating account: {err}");
            let mut err = admin_domain_account_get_impl(Some(session), domain, user_name, Some(DATABASE_ERROR)).await;
            err.override_status(rocket::http::Status::InternalServerError);
            return err;
        }
    };

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/accounts/{}", data.email)))
}
#[rocket::put("/admin/<domain>/accounts/<user_name>/user_permission", data = "<data>")]
pub async fn admin_domain_account_user_permission_put(
    session: Option<Session>,
    domain: &'_ str,
    user_name: &'_ str,
    data: rocket::form::Form<private::UpdateUserPermissions>,
) -> Return {
    let session = match session {
        None => return UNAUTH(domain).into(),
        Some(v) => v,
    };

    let no_perm = (rocket::http::Status::Forbidden, DomainBase{
        domain,
        content: MODIFY_ACCOUNT_NO_PERM,
    });
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm.into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.modify_accounts() {
        return no_perm.into();
    }

    let pool = crate::get_db().await;
    let self_user_id = session.get_user_id();
    let self_change_password = data.self_change_password;
    match sqlx::query!("MERGE INTO user_permission
    USING (
        SELECT users.id, $4::boolean as self_change_password FROM users
            JOIN flattened_web_domain_permissions perms ON perms.user_id = $3 AND perms.domain_id = users.domain_id
            JOIN flattened_domains domains ON users.domain_id = domains.id
            WHERE ($3 = ANY(domains.domain_owner) OR perms.admin OR perms.modify_accounts) AND
                  users.email = $1 AND users.domain_id = $2
    ) AS input ON user_permission.id = input.id
    WHEN MATCHED THEN UPDATE SET self_change_password = input.self_change_password
    WHEN NOT MATCHED THEN INSERT (id, self_change_password) VALUES (input.id, input.self_change_password)", user_name, permission.domain_id(), self_user_id, self_change_password).execute(&pool).await {
        Ok(_) => {  },
        Err(err) => {
            log::error!("Error creating account: {err}");
            let mut err = admin_domain_account_get_impl(Some(session), domain, user_name, Some(DATABASE_ERROR)).await;
            err.override_status(rocket::http::Status::InternalServerError);
            return err;
        }
    };

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/accounts/{user_name}")))
}
#[rocket::put("/admin/<domain>/accounts/<user_name>/password", data = "<data>")]
pub async fn admin_domain_account_password_put(
    session: Option<Session>,
    domain: &'_ str,
    user_name: &'_ str,
    data: rocket::form::Form<private::UpdateAccountPassword>,
) -> Return {
    let session = match session {
        None => return UNAUTH(domain).into(),
        Some(v) => v,
    };

    let no_perm = (rocket::http::Status::Forbidden, DomainBase{
        domain,
        content: MODIFY_ACCOUNT_NO_PERM,
    });
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm.into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.modify_accounts() {
        return no_perm.into();
    }

    let pool = crate::get_db().await;
    match set_password(pool, Err((user_name, permission.domain_id())), session.get_user_id(), data.into_inner().password).await {
        Err(err) => {
            log::error!("Error setting password: {err}");
            let mut err = admin_domain_account_get_impl(Some(session), domain, user_name, Some("There was an error setting the account Password.")).await;
            err.override_status(rocket::http::Status::InternalServerError);
            return err;
        }
        Ok(()) => {},
    }

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/accounts/{user_name}")))
}


#[rocket::put("/admin/<domain>/accounts/<user_name>/permissions", data = "<data>")]
pub async fn admin_domain_account_permissions_put(
    session: Option<Session>,
    domain: &'_ str,
    user_name: &'_ str,
    data: rocket::form::Form<UpdatePermissions>,
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
            let mut err = admin_domain_account_get_impl(Some(session), domain, user_name, Some(DATABASE_ERROR)).await;
            err.override_status(rocket::http::Status::InternalServerError);
            return err;
        }
    };

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/accounts/{user_name}")))
}
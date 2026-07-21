use crate::rocket::response::Return;
use crate::rocket::auth::check_password::set_password;
use crate::rocket::content::admin::domain::unauth;
use crate::rocket::content::admin::domain::account::admin_domain_account_get_impl;
use crate::rocket::messages::{ACCOUNT_INVALID_CHARS, DATABASE_ERROR, DATABASE_PERMISSION_ERROR, MANAGE_PERMISSION_NO_PERM, MODIFY_ACCOUNT_NO_PERM};
use crate::rocket::auth::session::Session;
use crate::rocket::auth::permissions::{UpdatePermissions};
use crate::rocket::template::authenticated::domain_base::DomainBase;

pub(super) mod private{
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct UpdateAccountEmail{
        pub email: String,
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct UpdateAccountPassword{
        pub password: String,
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct UpdateUserPermissions{
        pub self_change_password: bool,
    }
}

#[actix_web::post("/admin/<domain>/accounts/<user_name>/email")]
pub async fn admin_domain_account_email_put(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    user_name: String,
    data: actix_web::web::Form<private::UpdateAccountEmail>
) -> Return {
    let session = match &*session_ref {
        None => return unauth(domain).into(),
        Some(v) => v,
    };

    if !data.email.is_ascii() {
        return (actix_web::http::StatusCode::BAD_REQUEST, DomainBase{
            domain: domain.into(),
            content: ACCOUNT_INVALID_CHARS,
        }).into();
    }

    let no_perm =  |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: MODIFY_ACCOUNT_NO_PERM,
    });
    let permission = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.modify_accounts() {
        return no_perm(domain.into()).into();
    }

    let pool = crate::get_db().await;
    match sqlx::query!("SELECT set_user_email(users.id, $1, $2) as id from users WHERE email = $3 AND domain_id = $4",
        data.email, session.get_user_id(), user_name, permission.domain_id())
        .fetch_optional(&pool).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(Some(_)) => {},
        Ok(None) => return (actix_web::http::StatusCode::FORBIDDEN, DomainBase{
            domain: domain.into(),
            content: DATABASE_PERMISSION_ERROR,
        }).into(),
        Err(err) => {
            log::error!("Error updating account: {err}");
            return admin_domain_account_get_impl(&*session_ref, domain, user_name, Some(DATABASE_ERROR))
                .await
                .override_status(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    Return::redirect_to(format!("/admin/{domain}/accounts/{}", data.email))
}
#[actix_web::post("/admin/<domain>/accounts/<user_name>/user_permission")]
pub async fn admin_domain_account_user_permission_put(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    user_name: String,
    data: actix_web::web::Form<private::UpdateUserPermissions>,
) -> Return {
    let session = match &*session_ref {
        None => return unauth(domain).into(),
        Some(v) => v,
    };

    let no_perm = |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: MODIFY_ACCOUNT_NO_PERM,
    });
    let permission = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.modify_accounts() {
        return no_perm(domain.into()).into();
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
            return admin_domain_account_get_impl(&*session_ref, domain, user_name, Some(DATABASE_ERROR))
                .await
                .override_status(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    Return::redirect_to(format!("/admin/{domain}/accounts/{user_name}"))
}
#[actix_web::post("/admin/<domain>/accounts/<user_name>/password")]
pub async fn admin_domain_account_password_put(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    user_name: String,
    data: actix_web::web::Form<private::UpdateAccountPassword>,
) -> Return {
    let session = match &*session_ref {
        None => return unauth(domain).into(),
        Some(v) => v,
    };

    let no_perm = |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: MODIFY_ACCOUNT_NO_PERM,
    });
    let permission = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.modify_accounts() {
        return no_perm(domain.into()).into();
    }

    let pool = crate::get_db().await;
    match set_password(pool, Err((&user_name, permission.domain_id())), session.get_user_id(), data.into_inner().password).await {
        Err(err) => {
            log::error!("Error setting password: {err}");
            return admin_domain_account_get_impl(&*session_ref, domain, user_name, Some("There was an error setting the account Password."))
                .await
                .override_status(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(()) => {},
    }

    Return::redirect_to(format!("/admin/{domain}/accounts/{user_name}"))
}


#[actix_web::post("/admin/<domain>/accounts/<user_name>/permissions")]
pub async fn admin_domain_account_permissions_put(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    user_name: String,
    data: actix_web::web::Form<UpdatePermissions>,
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
            return admin_domain_account_get_impl(&*session_ref, domain, user_name, Some(DATABASE_ERROR))
                .await
                .override_status(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    Return::redirect_to(format!("/admin/{domain}/accounts/{user_name}"))
}
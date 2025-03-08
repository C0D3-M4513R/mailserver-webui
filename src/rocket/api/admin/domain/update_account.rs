use std::borrow::Cow;
use rocket::http::CookieJar;
use crate::rocket::auth::check_password::set_password;
use crate::rocket::content::admin::domain::{template, unauth_error};
use crate::rocket::content::admin::domain::account::admin_domain_account_get_impl;
use crate::rocket::messages::{DATABASE_ERROR, GET_PERMISSION_ERROR, MANAGE_PERMISSION_NO_PERM, MODIFY_ACCOUNT_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::session::Session;

mod private{
    #[derive(rocket::form::FromForm)]
    pub struct UpdateAccountEmail<'a>{
        pub email: &'a str,
    }
    #[derive(rocket::form::FromForm)]
    pub struct UpdateAccountPassword<'a>{
        pub password: &'a str,
    }
    #[derive(Debug, Default, Copy, Clone, rocket::form::FromForm)]
    pub struct Permission {
        pub admin: Option<bool>,
        pub view_domain: Option<bool>,
        pub list_subdomain: Option<bool>,
        pub create_subdomain: Option<bool>,
        pub delete_subdomain: Option<bool>,
        pub list_accounts: Option<bool>,
        pub create_accounts: Option<bool>,
        pub modify_accounts: Option<bool>,
        pub delete_accounts: Option<bool>,
        pub create_alias: Option<bool>,
        pub modify_alias: Option<bool>,
        pub list_permissions: Option<bool>,
        pub manage_permissions: Option<bool>,
    }
    impl Permission{
        pub fn remove_unassignable_permissions(&mut self, permission: &crate::rocket::session::Permission) {
            if !permission.get_admin() &&                                         !permission.get_admin()               { self.admin = None; }
            if !permission.get_admin() && !permission.get_manage_permissions() && !permission.get_view_domain()         { self.view_domain = None; }
            if !permission.get_admin() && !permission.get_manage_permissions() && !permission.get_list_subdomain()      { self.list_subdomain = None; }
            if !permission.get_admin() && !permission.get_manage_permissions() && !permission.get_create_subdomain()    { self.create_subdomain = None; }
            if !permission.get_admin() && !permission.get_manage_permissions() && !permission.get_delete_subdomain()    { self.delete_subdomain = None; }
            if !permission.get_admin() && !permission.get_manage_permissions() && !permission.get_list_accounts()       { self.list_accounts = None; }
            if !permission.get_admin() && !permission.get_manage_permissions() && !permission.get_create_accounts()     { self.create_accounts = None; }
            if !permission.get_admin() && !permission.get_manage_permissions() && !permission.get_modify_accounts()     { self.modify_accounts = None; }
            if !permission.get_admin() && !permission.get_manage_permissions() && !permission.get_delete_accounts()     { self.delete_accounts = None; }
            if !permission.get_admin() && !permission.get_manage_permissions() && !permission.get_create_alias()        { self.create_alias = None; }
            if !permission.get_admin() && !permission.get_manage_permissions() && !permission.get_modify_alias()        { self.modify_alias = None; }
            if !permission.get_admin() && !permission.get_manage_permissions() && !permission.get_list_permissions()    { self.list_permissions = None; }
            if !permission.get_admin() && !permission.get_manage_permissions() && !permission.get_manage_permissions()  { self.manage_permissions = None; }
        }
    }
}

#[rocket::put("/admin/<domain>/accounts/<user_id>/email", data = "<data>")]
pub async fn admin_domain_account_email_put(
    session: Option<Session>,
    domain: &'_ str,
    user_id: i64,
    data: rocket::form::Form<private::UpdateAccountEmail<'_>>,
    cookie_jar: &'_ CookieJar<'_>
) -> Return {
    let unauth_error = Return::Content((rocket::http::Status::Unauthorized, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(unauth_error(domain)),
    }));
    let mut session = match session {
        None => return unauth_error,
        Some(v) => v,
    };

    match session.refresh_permissions(cookie_jar).await{
        Ok(()) => {},
        Err(err) => {
            log::error!("Error refreshing permissions: {err}");
            return Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(template(domain, GET_PERMISSION_ERROR)),
            }));
        }
    }

    let no_perm = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, MODIFY_ACCOUNT_NO_PERM)),
    }));
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permission.get_admin() && !permission.get_create_accounts() {
        return no_perm;
    }

    let db = crate::get_mysql().await;
    match sqlx::query!("UPDATE virtual_users SET email = $1 WHERE id = $2", data.email, user_id).execute(db).await {
        Ok(_) => {  },
        Err(err) => {
            log::error!("Error creating account: {err}");
            let mut err = admin_domain_account_get_impl(Some(session), domain, user_id, Some(DATABASE_ERROR)).await;
            err.override_status(rocket::http::Status::InternalServerError);
            return err;
        }
    };

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/accounts/{user_id}")))
}
#[rocket::put("/admin/<domain>/accounts/<user_id>/password", data = "<data>")]
pub async fn admin_domain_account_password_put(
    session: Option<Session>,
    domain: &'_ str,
    user_id: i64,
    data: rocket::form::Form<private::UpdateAccountPassword<'_>>,
    cookie_jar: &'_ CookieJar<'_>
) -> Return {
    let unauth_error = Return::Content((rocket::http::Status::Unauthorized, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(unauth_error(domain)),
    }));
    let mut session = match session {
        None => return unauth_error,
        Some(v) => v,
    };

    match session.refresh_permissions(cookie_jar).await{
        Ok(()) => {},
        Err(err) => {
            log::error!("Error refreshing permissions: {err}");
            return Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(template(domain, GET_PERMISSION_ERROR)),
            }));
        }
    }

    let no_perm = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, MODIFY_ACCOUNT_NO_PERM)),
    }));
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permission.get_admin() && !permission.get_modify_accounts() {
        return no_perm;
    }

    let db = crate::get_mysql().await;
    let mut transaction = match db.begin().await {
        Ok(v) => v,
        Err(err) => {
            log::error!("Error beginning transaction: {err}");
            let mut err = admin_domain_account_get_impl(Some(session), domain, user_id, Some(DATABASE_ERROR)).await;
            err.override_status(rocket::http::Status::InternalServerError);
            return err;
        }
    };

    match set_password(&mut transaction, user_id, data.into_inner().password).await {
        Err(err) => {
            log::error!("Error setting password: {err}");
            let mut err = admin_domain_account_get_impl(Some(session), domain, user_id, Some("There was an error setting the account Password.")).await;
            err.override_status(rocket::http::Status::InternalServerError);
            return err;
        }
        Ok(()) => {},
    }

    match transaction.commit().await {
        Err(err) => {
            log::error!("Error comitting password change Transaction: {err}");
            let mut err = admin_domain_account_get_impl(Some(session), domain, user_id, Some("There was an error setting the account Password.")).await;
            err.override_status(rocket::http::Status::InternalServerError);
            return err;
        }
        Ok(()) => {},
    }


    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/accounts/{user_id}")))
}


#[rocket::put("/admin/<domain>/accounts/<user_id>/permissions", data = "<data>")]
pub async fn admin_domain_account_permissions_put(
    session: Option<Session>,
    domain: &'_ str,
    user_id: i64,
    data: rocket::form::Form<private::Permission>,
    cookie_jar: &'_ CookieJar<'_>
) -> Return {
    let unauth_error = Return::Content((rocket::http::Status::Unauthorized, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(unauth_error(domain)),
    }));
    let mut session = match session {
        None => return unauth_error,
        Some(v) => v,
    };

    match session.refresh_permissions(cookie_jar).await{
        Ok(()) => {},
        Err(err) => {
            log::error!("Error refreshing permissions: {err}");
            return Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(template(domain, GET_PERMISSION_ERROR)),
            }));
        }
    }

    let permission = match session.get_permissions().get(domain) {
        None => return unauth_error,
        Some(v) => v,
    };
    if !permission.get_admin() && !permission.get_manage_permissions() {
        return Return::Content((rocket::http::Status::Forbidden, TypedContent{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(template(domain, MANAGE_PERMISSION_NO_PERM)),
        }));
    }

    let mut user_permission = data.into_inner();
    user_permission.remove_unassignable_permissions(&permission);
    let user_permission = user_permission;

    let db = crate::get_mysql().await;

    match sqlx::query!("
MERGE INTO web_domain_permissions AS perm
    USING (
        SELECT
            $1::bigint AS domain_id,
            $2::bigint AS target_user_id,
            CASE WHEN slf.manage_permissions AND (slf.admin OR slf.admin)              THEN $4::bool  ELSE target.admin                 END AS admin,
            CASE WHEN slf.manage_permissions AND (slf.admin OR slf.view_domain)        THEN $5::bool  ELSE target.view_domain           END AS view_domain,
            CASE WHEN slf.manage_permissions AND (slf.admin OR slf.list_subdomain)     THEN $6::bool  ELSE target.list_subdomain        END AS list_subdomain,
            CASE WHEN slf.manage_permissions AND (slf.admin OR slf.create_subdomain)   THEN $7::bool  ELSE target.create_subdomain      END AS create_subdomain,
            CASE WHEN slf.manage_permissions AND (slf.admin OR slf.delete_subdomain)   THEN $8::bool  ELSE target.delete_subdomain      END AS delete_subdomain,
            CASE WHEN slf.manage_permissions AND (slf.admin OR slf.list_accounts)      THEN $9::bool  ELSE target.list_accounts         END AS list_accounts,
            CASE WHEN slf.manage_permissions AND (slf.admin OR slf.create_accounts)    THEN $10::bool ELSE target.create_accounts       END AS create_accounts,
            CASE WHEN slf.manage_permissions AND (slf.admin OR slf.modify_accounts)    THEN $11::bool ELSE target.modify_accounts       END AS modify_accounts,
            CASE WHEN slf.manage_permissions AND (slf.admin OR slf.delete_accounts)    THEN $12::bool ELSE target.delete_accounts       END AS delete_accounts,
            CASE WHEN slf.manage_permissions AND (slf.admin OR slf.create_alias)       THEN $13::bool ELSE target.create_alias          END AS create_alias,
            CASE WHEN slf.manage_permissions AND (slf.admin OR slf.modify_alias)       THEN $14::bool ELSE target.modify_alias          END AS modify_alias,
            CASE WHEN slf.manage_permissions AND (slf.admin OR slf.list_permissions)   THEN $15::bool ELSE target.list_permissions      END AS list_permissions,
            CASE WHEN slf.admin AND slf.manage_permissions                             THEN $16::bool ELSE target.manage_permissions    END AS manage_permissions
        FROM web_domain_permissions target
            JOIN flattened_web_domain_permissions slf ON slf.domain_id = target.domain_id AND slf.user_id = $3
        WHERE target.domain_id = $1 AND target.user_id = $2
   ) AS row ON perm.domain_id = row.domain_id AND perm.user_id = row.target_user_id
WHEN MATCHED THEN
    UPDATE SET
        domain_id = row.domain_id,
        user_id = row.target_user_id,
        admin = row.admin,
        view_domain = row.view_domain,
        list_subdomain = row.list_subdomain,
        create_subdomain = row.create_subdomain,
        delete_subdomain = row.delete_subdomain,
        list_accounts = row.list_accounts,
        create_accounts = row.create_accounts,
        modify_accounts = row.modify_accounts,
        delete_accounts = row.delete_accounts,
        create_alias = row.create_alias,
        modify_alias = row.modify_alias,
        list_permissions = row.list_permissions,
        manage_permissions = row.manage_permissions
WHEN NOT MATCHED THEN
    INSERT (
        domain_id,
        user_id,
        admin,
        view_domain,
        list_subdomain,
        create_subdomain,
        delete_subdomain,
        list_accounts,
        create_accounts,
        modify_accounts,
        delete_accounts,
        create_alias,
        modify_alias,
        list_permissions,
        manage_permissions
    ) VALUES (
        row.domain_id,
        row.target_user_id,
        row.admin,
        row.view_domain,
        row.list_subdomain,
        row.create_subdomain,
        row.delete_subdomain,
        row.list_accounts,
        row.create_accounts,
        row.modify_accounts,
        row.delete_accounts,
        row.create_alias,
        row.modify_alias,
        row.list_permissions,
        row.manage_permissions
    )
    ",  permission.get_domain_id(), user_id, session.get_user_id(),
user_permission.admin,
user_permission.view_domain,
user_permission.list_subdomain,
user_permission.create_subdomain,
user_permission.delete_subdomain,
user_permission.list_accounts,
user_permission.create_accounts,
user_permission.modify_accounts,
user_permission.delete_accounts,
user_permission.create_alias,
user_permission.modify_alias,
user_permission.list_permissions,
user_permission.manage_permissions,
    ).execute(db).await {
        Ok(_) => {  },
        Err(err) => {
            log::error!("Error creating account: {err}");
            let mut err = admin_domain_account_get_impl(Some(session), domain, user_id, Some(DATABASE_ERROR)).await;
            err.override_status(rocket::http::Status::InternalServerError);
            return err;
        }
    };

    if user_id == session.get_user_id() {
        match session.refresh_permissions(cookie_jar).await{
            Ok(()) => {},
            Err(err) => {
                log::error!("Error refreshing permissions: {err}");
                return Return::Content((rocket::http::Status::Forbidden, TypedContent{
                    content_type: rocket::http::ContentType::HTML,
                    content: Cow::Owned(template(domain, GET_PERMISSION_ERROR)),
                }));
            }
        }
    }

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/accounts/{user_id}")))
}
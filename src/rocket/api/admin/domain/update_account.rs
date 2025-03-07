use std::borrow::Cow;
use rocket::http::CookieJar;
use crate::rocket::auth::check_password::set_password;
use crate::rocket::content::admin::domain::{accounts::admin_domain_accounts_get_impl, template, unauth_error};
use crate::rocket::content::admin::domain::account::admin_domain_account_get_impl;
use crate::rocket::messages::{DATABASE_ERROR, GET_PERMISSION_ERROR};
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
}

#[rocket::put("/admin/<domain>/accounts/<user_id>/email", data = "<data>")]
pub async fn admin_domain_account_email_put(
    mut session: Session,
    domain: &'_ str,
    user_id: i32,
    data: rocket::form::Form<private::UpdateAccountEmail<'_>>,
    cookie_jar: &'_ CookieJar<'_>
) -> Return {
    let unauth_error = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(unauth_error(domain)),
    }));
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

    let permission = match session.get_permissions().get(domain) {
        None => return unauth_error,
        Some(v) => v,
    };
    if !permission.get_admin() && !permission.get_create_accounts() {
        return unauth_error
    }

    let db = crate::get_mysql().await;
    let mut transaction = match db.begin().await {
        Ok(v) => v,
        Err(err) => {
            log::error!("Error beginning transaction: {err}");
            return admin_domain_accounts_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
        }
    };

    match sqlx::query!("UPDATE virtual_users SET email = $1 WHERE id = $2", data.email, user_id).execute(db).await {
        Ok(v) => {  },
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
    mut session: Session,
    domain: &'_ str,
    user_id: i32,
    data: rocket::form::Form<private::UpdateAccountPassword<'_>>,
    cookie_jar: &'_ CookieJar<'_>
) -> Return {
    let unauth_error = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(unauth_error(domain)),
    }));
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

    let permission = match session.get_permissions().get(domain) {
        None => return unauth_error,
        Some(v) => v,
    };
    if !permission.get_admin() && !permission.get_modify_accounts() {
        return unauth_error
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

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/accounts/{user_id}")))
}
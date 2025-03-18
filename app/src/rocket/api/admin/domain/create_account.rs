use std::borrow::Cow;
use crate::rocket::auth::check_password::get_password_hash;
use crate::rocket::content::admin::domain::{accounts::admin_domain_accounts_get_impl, template, unauth_error};
use crate::rocket::messages::{ACCOUNT_INVALID_CHARS, CREATE_ACCOUNT_NO_PERM, DATABASE_ERROR, DATABASE_PERMISSION_ERROR};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::Session;

mod private{
    #[derive(serde::Deserialize, serde::Serialize, rocket::form::FromForm)]
    pub struct CreateAccount<'a>{
        pub email: &'a str,
        pub password: String,
    }
}

#[rocket::put("/admin/<domain>/accounts", data = "<data>")]
pub async fn create_account(
    session: Option<Session>,
    domain: &'_ str,
    data: rocket::form::Form<private::CreateAccount<'_>>
) -> Return {
    let unauth_error = Return::Content((rocket::http::Status::Unauthorized, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(unauth_error(domain)),
    }));
    let session = match session {
        None => return unauth_error,
        Some(v) => v,
    };

    if !data.email.is_ascii() {
        return Return::Content((rocket::http::Status::BadRequest, TypedContent{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(template(domain, ACCOUNT_INVALID_CHARS)),
        }));
    }

    let pool = crate::get_mysql().await;

    let no_perm = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, CREATE_ACCOUNT_NO_PERM)),
    }));
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permission.admin() && !permission.create_accounts() {
        return no_perm;
    }

    let mut transaction = match pool.begin().await {
        Ok(v) => v,
        Err(err) => {
            log::error!("Error beginning transaction: {err}");
            return admin_domain_accounts_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
        }
    };
    let data = data.into_inner();
    let hash = match get_password_hash(data.password).await {
        Err(err) =>  {
            log::error!("Error getting password hash: {err}");
            let mut result = admin_domain_accounts_get_impl(Some(session), domain, Some("There was an error setting the account Password.")).await;
            result.override_status(rocket::http::Status::InternalServerError);
            return result;
        },
        Ok(v) => v,
    };
    match sqlx::query!("SELECT insert_new_account($1, $2, $3, '{ARGON2ID}', $4) as id", permission.domain_id(), data.email, hash, session.get_user_id())
        .fetch_optional(&mut *transaction).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(Some(v)) => v,
        Ok(None) => {
            log::error!("Error creating account: DB permission check failed");
            let mut result = admin_domain_accounts_get_impl(Some(session), domain, Some(DATABASE_PERMISSION_ERROR)).await;
            result.override_status(rocket::http::Status::Forbidden);
            return result;
        },
        Err(err) => {
            log::error!("Error creating account: {err}");
            let mut result = admin_domain_accounts_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
            result.override_status(rocket::http::Status::InternalServerError);
            return result;
        }
    };

    match transaction.commit().await {
        Ok(()) => {},
        Err(err) => {
            log::error!("Error commiting account: {err}");
            let mut result = admin_domain_accounts_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
            result.override_status(rocket::http::Status::InternalServerError);
            return result;
        }
    }

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/accounts")))
}
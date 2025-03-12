use std::borrow::Cow;
use crate::rocket::content::admin::domain::{template, unauth_error};
use crate::rocket::messages::{ALIAS_INVALID_CHARS, CREATE_ALIAS_NO_PERM, DATABASE_ERROR};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::Session;
use crate::rocket::content::admin::domain::aliases::admin_domain_aliases_get_impl;

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
    let unauth_error = Return::Content((rocket::http::Status::Unauthorized, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(unauth_error(domain)),
    }));
    let session = match session {
        None => return unauth_error,
        Some(v) => v,
    };

    if !data.source.is_ascii() {
        return Return::Content((rocket::http::Status::BadRequest, TypedContent{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(template(domain, ALIAS_INVALID_CHARS)),
        }));
    }

    let pool = crate::get_mysql().await;

    let no_perm = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, CREATE_ALIAS_NO_PERM)),
    }));
    let permission = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permission.admin() && !permission.create_alias() {
        return no_perm;
    }

    match sqlx::query!("
WITH valid_values AS (
    SELECT $1::text as src, target.id FROM virtual_users target
        JOIN flattened_web_domain_permissions perms ON perms.domain_id = target.domain_id AND perms.user_id = $4
        WHERE target.id = $3 AND (perms.is_owner OR perms.admin OR perms.list_accounts)
) INSERT INTO virtual_aliases (source, domain_id, destination) SELECT src, $2, id FROM valid_values
", data.source, permission.domain_id(), data.user, session.get_user_id()).execute(pool).await {
        Ok(_) => {},
        Err(err) => {
            log::error!("Error creating account: {err}");
            let mut result = admin_domain_aliases_get_impl(Some(session), domain, Some(DATABASE_ERROR)).await;
            result.override_status(rocket::http::Status::InternalServerError);
            return result;
        }
    };

    Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/aliases")))
}
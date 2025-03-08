use std::borrow::Cow;
use crate::rocket::content::admin::domain::{template, unauth_error};
use crate::rocket::messages::{DELETE_ACCOUNT_NO_PERM, DATABASE_ERROR, GET_PERMISSION_ERROR};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::session::Session;

mod private {
    use std::collections::HashMap;

    #[derive(Debug, rocket::form::FromForm)]
    pub struct DeleteAccounts{
        pub accounts: HashMap<i64, bool>,
    }
}

#[rocket::delete("/admin/<domain>/accounts/<user_id>")]
pub async fn admin_domain_account_delete(
    session: Session,
    domain: &str,
    user_id: i64,
    cookie_jar: &'_ rocket::http::CookieJar<'_>,
) -> Return {
    let mut accounts = std::collections::HashMap::new();
    accounts.insert(user_id, true);
    admin_domain_accounts_delete(session, domain, ::rocket::form::Form::from(private::DeleteAccounts{accounts}), cookie_jar).await
}

#[rocket::delete("/admin/<domain>/accounts", data="<data>")]
pub async fn admin_domain_accounts_delete(
    mut session: Session,
    domain: &str,
    data: ::rocket::form::Form<private::DeleteAccounts>,
    cookie_jar: &'_ rocket::http::CookieJar<'_>,
) -> Return {
    let unauth = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(unauth_error(domain)),
    }));

    match session.refresh_permissions(cookie_jar).await {
        Ok(()) => {},
        Err(err) => {
            log::error!("Error refreshing permissions: {err}");
            return Return::Content((rocket::http::Status::Forbidden, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(template(domain, GET_PERMISSION_ERROR)),
            }));
        }
    }

    let permissions = match session.get_permissions().get(domain) {
        None => return Return::Content((rocket::http::Status::Forbidden, TypedContent{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(template(domain, DELETE_ACCOUNT_NO_PERM)),
        })),
        Some(v) => v,
    };

    if !permissions.get_admin() && !permissions.get_delete_accounts(){
        return unauth;
    }

    let db_error = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, DATABASE_ERROR)),
    }));

    let db = crate::get_mysql().await;
    let accounts = data.into_inner().accounts.into_iter().filter_map(|(k, v)|if v {Some(k)} else {None}).collect::<Vec<_>>();
    match sqlx::query!(
        r#"
        DELETE FROM virtual_users users
           WHERE users.id = ANY($1) AND users.domain_id IN (SELECT id FROM virtual_domains WHERE name = $2)
        "#,
        &accounts,
        domain
    ).execute(db).await {
        Ok(_) => Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/accounts"))),
        Err(err) => {
            log::error!("Error deleting accounts: {err}");
            db_error
        }
    }

}
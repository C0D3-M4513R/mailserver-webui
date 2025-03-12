use std::borrow::Cow;
use crate::rocket::content::admin::domain::{template, unauth_error};
use crate::rocket::messages::{DELETE_ACCOUNT_NO_PERM, DATABASE_ERROR};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::Session;

mod private {
    use std::collections::HashMap;

    #[derive(Debug, rocket::form::FromForm)]
    pub struct DeleteAccounts{
        pub accounts: HashMap<i64, bool>,
    }
}

#[rocket::delete("/admin/<domain>/accounts/<user_id>")]
pub async fn admin_domain_account_delete(
    session: Option<Session>,
    domain: &str,
    user_id: i64
) -> Return {
    let mut accounts = std::collections::HashMap::new();
    accounts.insert(user_id, true);
    admin_domain_accounts_delete(session, domain, ::rocket::form::Form::from(private::DeleteAccounts{accounts})).await
}

#[rocket::delete("/admin/<domain>/accounts", data="<data>")]
pub async fn admin_domain_accounts_delete(
    session: Option<Session>,
    domain: &str,
    data: ::rocket::form::Form<private::DeleteAccounts>
) -> Return {
    let unauth = Return::Content((rocket::http::Status::Unauthorized, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(unauth_error(domain)),
    }));
    let session = match session {
        None => return unauth,
        Some(v) => v,
    };

    let pool = crate::get_mysql().await;

    let no_perm = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, DELETE_ACCOUNT_NO_PERM)),
    }));
    let permissions = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permissions.admin() && !permissions.delete_accounts(){
        return no_perm;
    }

    let db_error = Return::Content((rocket::http::Status::InternalServerError, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, DATABASE_ERROR)),
    }));

    let accounts = data.into_inner().accounts.into_iter().filter_map(|(k, v)|if v {Some(k)} else {None}).collect::<Vec<_>>();
    let domain_id = permissions.domain_id();
    match sqlx::query!(
        r#"
        DELETE FROM virtual_users users
           WHERE users.id = ANY($1) AND users.domain_id = $2
        "#,
        &accounts,
        domain_id
    ).execute(pool).await {
        Ok(_) => Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/accounts"))),
        Err(err) => {
            log::error!("Error deleting accounts: {err}");
            db_error
        }
    }

}
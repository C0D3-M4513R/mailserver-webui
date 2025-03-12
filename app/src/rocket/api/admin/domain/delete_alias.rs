use std::borrow::Cow;
use rocket::response::Redirect;
use crate::rocket::content::admin::domain::{template, unauth_error};
use crate::rocket::messages::{DATABASE_ERROR, DELETE_ALIAS_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::Session;

mod private {
    use std::collections::HashMap;

    #[derive(Debug, rocket::form::FromForm)]
    pub struct DeleteAliases {
        pub aliases: HashMap<i64, bool>,
    }
}

#[rocket::delete("/admin/<domain>/aliases", data="<data>")]
pub async fn admin_domain_aliases_delete(
    session: Option<Session>,
    domain: &str,
    data: ::rocket::form::Form<private::DeleteAliases>,
) -> Return {
    admin_domain_aliases_delete_impl(session, domain, None, data, Redirect::to(format!("/admin/{domain}/aliases"))).await
}
#[rocket::delete("/admin/<domain>/accounts/<account_name>/aliases", data="<data>")]
pub async fn admin_domain_account_aliases_delete(
    session: Option<Session>,
    domain: &str,
    account_name: &str,
    data: ::rocket::form::Form<private::DeleteAliases>,
) -> Return {
    admin_domain_aliases_delete_impl(session, domain, Some(account_name), data, Redirect::to(format!("/admin/{domain}/accounts/{account_name}"))).await
}

async fn admin_domain_aliases_delete_impl(
    session: Option<Session>,
    domain: &str,
    account_name: Option<&str>,
    data: ::rocket::form::Form<private::DeleteAliases>,
    success_redirect: Redirect
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
        content: Cow::Owned(template(domain, DELETE_ALIAS_NO_PERM)),
    }));
    let permissions = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permissions.admin() && !permissions.delete_alias(){
        return no_perm;
    }

    let db_error = Return::Content((rocket::http::Status::InternalServerError, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, DATABASE_ERROR)),
    }));

    let alias_ids = data.into_inner().aliases.into_iter().filter_map(|(k, v)|if v {Some(k)} else {None}).collect::<Vec<_>>();
    match sqlx::query!(r#"
DELETE FROM virtual_aliases alias
       USING users
       WHERE alias.id = ANY($1) AND users.id = alias.destination AND users.domain_id = $2 AND
            ($3::text IS NULL OR $3::text = users.email)
        "#,
        &alias_ids,
        permissions.domain_id(),
        account_name
    ).execute(pool).await {
        Ok(_) => Return::Redirect(success_redirect),
        Err(err) => {
            log::error!("Error deleting alias: {err}");
            db_error
        }
    }
}
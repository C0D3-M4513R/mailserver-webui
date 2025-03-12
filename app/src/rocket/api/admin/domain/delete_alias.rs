use std::borrow::Cow;
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

    let domains = data.into_inner().aliases.into_iter().filter_map(|(k, v)|if v {Some(k)} else {None}).collect::<Vec<_>>();
    match sqlx::query!(r#"
DELETE FROM virtual_aliases alias WHERE alias.id = ANY($1)
        "#,
        &domains,
    ).execute(pool).await {
        Ok(_) => Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/aliases"))),
        Err(err) => {
            log::error!("Error deleting alias: {err}");
            db_error
        }
    }

}
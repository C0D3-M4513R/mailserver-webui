use std::collections::HashSet;
use rocket::response::Redirect;
use crate::rocket::content::admin::domain::UNAUTH;
use crate::rocket::messages::{DATABASE_ERROR, DELETE_ALIAS_NO_PERM};
use crate::rocket::response::Return;
use crate::rocket::auth::session::Session;
use crate::rocket::template::authenticated::domain_base::DomainBase;

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
    admin_domain_aliases_delete_impl(session, domain, data, Redirect::to(format!("/admin/{domain}/aliases"))).await
}
#[rocket::delete("/admin/<domain>/accounts/<account_name>/aliases", data="<data>")]
pub async fn admin_domain_account_aliases_delete(
    session: Option<Session>,
    domain: &str,
    account_name: &str,
    data: ::rocket::form::Form<private::DeleteAliases>,
) -> Return {
    admin_domain_aliases_delete_impl(session, domain, data, Redirect::to(format!("/admin/{domain}/accounts/{account_name}"))).await
}

async fn admin_domain_aliases_delete_impl(
    session: Option<Session>,
    domain: &str,
    data: ::rocket::form::Form<private::DeleteAliases>,
    success_redirect: Redirect
) -> Return {
    let session = match session {
        None => return UNAUTH(domain).into(),
        Some(v) => v,
    };

    let no_perm = (rocket::http::Status::Forbidden, DomainBase{
        domain,
        content: DELETE_ALIAS_NO_PERM,
    });
    let permissions = match session.get_permissions().get(domain) {
        None => return no_perm.into(),
        Some(v) => v,
    };
    if !permissions.admin() && !permissions.delete_alias(){
        return no_perm.into();
    }

    let db_error = (rocket::http::Status::InternalServerError, DomainBase{
        domain,
        content: DATABASE_ERROR,
    });

    let pool = crate::get_db().await;
    let alias_ids = data.into_inner().aliases.into_iter().filter_map(|(k, v)|if v {Some(k)} else {None}).collect::<Vec<_>>();
    match sqlx::query!(r#"SELECT delete_alias($1, $2) as id"#,
        &alias_ids,
        session.get_user_id()
    ).fetch_all(&pool).await {
        Ok(v) => {
            let aliases = HashSet::from_iter(alias_ids.iter().copied());
            let processed_aliases = v.into_iter().filter_map(|v|v.id).collect::<HashSet<_>>();
            if aliases.len() != processed_aliases.len() {
                let not_recovered = aliases.difference(&processed_aliases).collect::<Vec<_>>();
                let extra_recovered = processed_aliases.difference(&aliases).collect::<Vec<_>>();
                if not_recovered.len() > 0 {
                    log::warn!("Error deleting aliases. User {} tried deleting aliases {not_recovered:?}, for which he didn't have permission", session.get_user_id());
                }
                if extra_recovered.len() > 0 {
                    log::error!("Error deleting aliases. User {} tried deleting aliases {alias_ids:?}, but we additionally recovered {extra_recovered:?} ", session.get_user_id());
                }
            }
            Return::Redirect(success_redirect)
        },
        Err(err) => {
            log::error!("Error deleting alias: {err}");
            db_error.into()
        }
    }
}
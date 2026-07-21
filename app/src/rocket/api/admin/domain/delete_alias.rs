use std::collections::HashSet;
use crate::rocket::content::admin::domain::unauth;
use crate::rocket::messages::{DATABASE_ERROR, DELETE_ALIAS_NO_PERM};
use crate::rocket::response::Return;
use crate::rocket::auth::session::Session;
use crate::rocket::template::authenticated::domain_base::DomainBase;

mod private {
    use std::collections::HashMap;

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct DeleteAliases {
        pub aliases: HashMap<i64, bool>,
    }
}

#[actix_web::post("/admin/<domain>/aliases/delete")]
pub async fn admin_domain_aliases_delete(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    data: ::actix_web::web::Form<private::DeleteAliases>,
) -> Return {
    let ret = Return::redirect_to(format!("/admin/{domain}/aliases"));
    admin_domain_aliases_delete_impl(&*session_ref, domain, data, ret).await
}
#[actix_web::post("/admin/<domain>/accounts/<account_name>/aliases/delete")]
pub async fn admin_domain_account_aliases_delete(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    account_name: String,
    data: ::actix_web::web::Form<private::DeleteAliases>,
) -> Return {
    let ret = Return::redirect_to(format!("/admin/{domain}/accounts/{account_name}"));
    admin_domain_aliases_delete_impl(&*session_ref, domain, data, ret).await
}

async fn admin_domain_aliases_delete_impl(
    session_ref: &Option<Session>,
    domain: String,
    data: ::actix_web::web::Form<private::DeleteAliases>,
    success_redirect: Return
) -> Return {
    let session = match session_ref {
        None => return unauth(domain).into(),
        Some(v) => v,
    };

    let no_perm = |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: DELETE_ALIAS_NO_PERM,
    });
    let permissions = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permissions.admin() && !permissions.delete_alias(){
        return no_perm(domain.into()).into();
    }

    let db_error = |domain|(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, DomainBase{
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
            success_redirect
        },
        Err(err) => {
            log::error!("Error deleting alias: {err}");
            db_error(domain.into()).into()
        }
    }
}
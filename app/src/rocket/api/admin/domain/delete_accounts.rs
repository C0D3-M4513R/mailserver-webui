use std::collections::HashSet;
use crate::rocket::content::admin::domain::unauth;
use crate::rocket::messages::{DELETE_ACCOUNT_NO_PERM, DATABASE_ERROR, DELETE_DISABLED_NO_PERM, UNDELETE_DISABLED_NO_PERM};
use crate::rocket::response::Return;
use crate::rocket::auth::session::Session;
use crate::rocket::template::authenticated::domain_base::DomainBase;

mod private {
    use std::collections::HashMap;

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct AccountId {
        pub id: i64
    }

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct AccountSelection {
        pub accounts: HashMap<i64, bool>,
    }
}

#[actix_web::post("/admin/<domain>/accounts/<_>/delete")]
pub async fn admin_domain_account_delete(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    data: ::actix_web::web::Form<private::AccountId>
) -> Return {
    let mut accounts = std::collections::HashMap::with_capacity(1);
    accounts.insert(data.id, true);
    admin_domain_accounts_delete_impl(&*session_ref, domain, ::actix_web::web::Form(private::AccountSelection {accounts})).await
}

#[actix_web::post("/admin/<domain>/accounts/disable")]
pub async fn admin_domain_accounts_delete(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    data: ::actix_web::web::Form<private::AccountSelection>
) -> Return {
    admin_domain_accounts_delete_impl(&*session_ref, domain, data).await
}

pub async fn admin_domain_accounts_delete_impl(
    session: &Option<Session>,
    domain: String,
    data: ::actix_web::web::Form<private::AccountSelection>
) -> Return {
    let session = match session {
        None => return unauth(domain).into(),
        Some(v) => v,
    };

    let no_perm = |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: DELETE_ACCOUNT_NO_PERM,
    });
    let permissions = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permissions.admin() && !permissions.delete_accounts(){
        return no_perm(domain.into()).into();
    }

    let db_error = |domain|(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, DomainBase{
        domain,
        content: DATABASE_ERROR,
    });

    let pool = crate::get_db().await;
    let accounts = data.into_inner().accounts.into_iter().filter_map(|(k, v)|if v {Some(k)} else {None}).collect::<Vec<_>>();
    match sqlx::query!(r#"SELECT disable_users($1, $2) as id"#,
        &accounts,
        session.get_user_id()
    ).fetch_all(&pool).await {
        Ok(v) => {
            let accounts = HashSet::from_iter(accounts);
            let processed_accounts = v.into_iter().filter_map(|v|v.id).collect::<HashSet<_>>();
            if accounts.len() != processed_accounts.len() {
                let not_recovered = accounts.difference(&processed_accounts).collect::<Vec<_>>();
                let extra_recovered = processed_accounts.difference(&accounts).collect::<Vec<_>>();
                if not_recovered.len() > 0 {
                    log::warn!("Error disabling accounts. User {} tried disabling accounts {not_recovered:?}, for which he didn't have permission", session.get_user_id());
                }
                if extra_recovered.len() > 0 {
                    log::error!("Error disabling accounts. User {} tried disabling accounts {accounts:?}, but we additionally recovered {extra_recovered:?} ", session.get_user_id());
                }
            }
            Return::redirect_to(format!("/admin/{domain}/accounts"))
        },
        Err(err) => {
            log::error!("Error deleting accounts: {err}");
            db_error(domain.into()).into()
        }
    }

}

#[actix_web::post("/admin/<domain>/accounts/delete")]
pub async fn admin_domain_accounts_delete_post(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    data: ::actix_web::web::Form<private::AccountSelection>
) -> Return {
    let session = match &*session_ref {
        None => return unauth(domain).into(),
        Some(v) => v,
    };

    let no_perm = |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: DELETE_DISABLED_NO_PERM,
    });
    let permissions = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permissions.admin() && !(permissions.delete_disabled() && permissions.list_deleted()) {
        return no_perm(domain.into()).into();
    }

    let db_error =  |domain|(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, DomainBase{
        domain,
        content: DATABASE_ERROR,
    });

    let pool = crate::get_db().await;
    let accounts = data.into_inner().accounts.into_iter().filter_map(|(k, v)|if v {Some(k)} else {None}).collect::<Vec<_>>();
    match sqlx::query!(r#"SELECT delete_users($1, $2) as id"#,
        &accounts,
        session.get_user_id()
    ).fetch_all(&pool).await {
        Ok(v) => {
            let accounts = HashSet::from_iter(accounts);
            let processed_accounts = v.into_iter().filter_map(|v|v.id).collect::<HashSet<_>>();
            if accounts.len() != processed_accounts.len() {
                let not_recovered = accounts.difference(&processed_accounts).collect::<Vec<_>>();
                let extra_recovered = processed_accounts.difference(&accounts).collect::<Vec<_>>();
                if not_recovered.len() > 0 {
                    log::warn!("Error deleting accounts. User {} tried deleting accounts {not_recovered:?}, for which he didn't have permission", session.get_user_id());
                }
                if extra_recovered.len() > 0 {
                    log::error!("Error deleting accounts. User {} tried deleting accounts {accounts:?}, but we additionally recovered {extra_recovered:?} ", session.get_user_id());
                }
            }
            Return::redirect_to(format!("/admin/{domain}/accounts"))
        },
        Err(err) => {
            log::error!("Error deleting accounts: {err}");
            db_error(domain.into()).into()
        }
    }
}
#[actix_web::post("/admin/<domain>/accounts/restore")]
pub async fn admin_domain_accounts_restore_post(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    data: ::actix_web::web::Form<private::AccountSelection>
) -> Return {
    let session = match &*session_ref {
        None => return unauth(domain).into(),
        Some(v) => v,
    };

    let no_perm = |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: UNDELETE_DISABLED_NO_PERM,
    });
    let permissions = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permissions.admin() && !(permissions.undelete() && permissions.list_accounts()){
        return no_perm(domain.into()).into();
    }

    let db_error = |domain|(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, DomainBase{
        domain,
        content: DATABASE_ERROR,
    });

    let pool = crate::get_db().await;
    let accounts = data.into_inner().accounts.into_iter().filter_map(|(k, v)|if v {Some(k)} else {None}).collect::<Vec<_>>();
    match sqlx::query!(r#"SELECT recover_users($1, $2) as id"#,
        &accounts,
        session.get_user_id()
    ).fetch_all(&pool).await {
        Ok(v) => {
            let accounts = HashSet::from_iter(accounts);
            let processed_accounts = v.into_iter().filter_map(|v|v.id).collect::<HashSet<_>>();
            if accounts.len() != processed_accounts.len() {
                let not_recovered = accounts.difference(&processed_accounts).collect::<Vec<_>>();
                let extra_recovered = processed_accounts.difference(&accounts).collect::<Vec<_>>();
                if not_recovered.len() > 0 {
                    log::warn!("Error restoring accounts. User {} tried restoring accounts {not_recovered:?}, for which he didn't have permission", session.get_user_id());
                }
                if extra_recovered.len() > 0 {
                    log::error!("Error restoring accounts. User {} tried restoring accounts {accounts:?}, but we additionally recovered {extra_recovered:?} ", session.get_user_id());
                }
            }
            Return::redirect_to(format!("/admin/{domain}/accounts"))
        },
        Err(err) => {
            log::error!("Error restoring accounts: {err}");
            db_error(domain.into()).into()
        }
    }
}
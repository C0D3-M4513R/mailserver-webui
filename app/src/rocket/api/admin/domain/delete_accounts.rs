use std::collections::HashSet;
use crate::rocket::content::admin::domain::UNAUTH;
use crate::rocket::messages::{DELETE_ACCOUNT_NO_PERM, DATABASE_ERROR, DELETE_DISABLED_NO_PERM, UNDELETE_DISABLED_NO_PERM};
use crate::rocket::response::Return;
use crate::rocket::auth::session::Session;
use crate::rocket::template::authenticated::domain_base::DomainBase;

mod private {
    use std::collections::HashMap;

    #[derive(Debug, rocket::form::FromForm)]
    pub struct AccountId {
        pub id: i64
    }

    #[derive(Debug, rocket::form::FromForm)]
    pub struct AccountSelection {
        pub accounts: HashMap<i64, bool>,
    }
}

#[rocket::delete("/admin/<domain>/accounts/<_>", data="<data>")]
pub async fn admin_domain_account_delete(
    session: Option<Session>,
    domain: &str,
    data: ::rocket::form::Form<private::AccountId>
) -> Return {
    let mut accounts = std::collections::HashMap::new();
    accounts.insert(data.id, true);
    admin_domain_accounts_delete(session, domain, ::rocket::form::Form::from(private::AccountSelection {accounts})).await
}

#[rocket::delete("/admin/<domain>/accounts", data="<data>")]
pub async fn admin_domain_accounts_delete(
    session: Option<Session>,
    domain: &str,
    data: ::rocket::form::Form<private::AccountSelection>
) -> Return {
    let session = match session {
        None => return UNAUTH(domain).into(),
        Some(v) => v,
    };


    let no_perm = (rocket::http::Status::Forbidden, DomainBase{
        domain,
        content: DELETE_ACCOUNT_NO_PERM,
    });
    let permissions = match session.get_permissions().get(domain) {
        None => return no_perm.into(),
        Some(v) => v,
    };
    if !permissions.admin() && !permissions.delete_accounts(){
        return no_perm.into();
    }

    let db_error = (rocket::http::Status::InternalServerError, DomainBase{
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
            Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/accounts")))
        },
        Err(err) => {
            log::error!("Error deleting accounts: {err}");
            db_error.into()
        }
    }

}

#[rocket::post("/admin/<domain>/accounts/delete", data="<data>")]
pub async fn admin_domain_accounts_delete_post(
    session: Option<Session>,
    domain: &str,
    data: ::rocket::form::Form<private::AccountSelection>
) -> Return {
    let session = match session {
        None => return UNAUTH(domain).into(),
        Some(v) => v,
    };

    let no_perm = (rocket::http::Status::Forbidden, DomainBase{
        domain,
        content: DELETE_DISABLED_NO_PERM,
    });
    let permissions = match session.get_permissions().get(domain) {
        None => return no_perm.into(),
        Some(v) => v,
    };
    if !permissions.admin() && !(permissions.delete_disabled() && permissions.list_deleted()) {
        return no_perm.into();
    }

    let db_error = (rocket::http::Status::InternalServerError, DomainBase{
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
            Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/accounts")))
        },
        Err(err) => {
            log::error!("Error deleting accounts: {err}");
            db_error.into()
        }
    }
}
#[rocket::post("/admin/<domain>/accounts/restore", data="<data>")]
pub async fn admin_domain_accounts_restore_post(
    session: Option<Session>,
    domain: &str,
    data: ::rocket::form::Form<private::AccountSelection>
) -> Return {
    let session = match session {
        None => return UNAUTH(domain).into(),
        Some(v) => v,
    };

    let no_perm = (rocket::http::Status::Forbidden, DomainBase{
        domain,
        content: UNDELETE_DISABLED_NO_PERM,
    });
    let permissions = match session.get_permissions().get(domain) {
        None => return no_perm.into(),
        Some(v) => v,
    };
    if !permissions.admin() && !(permissions.undelete() && permissions.list_accounts()){
        return no_perm.into();
    }

    let db_error = (rocket::http::Status::InternalServerError, DomainBase{
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
            Return::Redirect(rocket::response::Redirect::to(format!("/admin/{domain}/accounts")))
        },
        Err(err) => {
            log::error!("Error restoring accounts: {err}");
            db_error.into()
        }
    }
}
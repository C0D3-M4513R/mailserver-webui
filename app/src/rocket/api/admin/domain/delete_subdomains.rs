use std::collections::HashSet;
use crate::rocket::content::admin::domain::unauth;
use crate::rocket::messages::{DATABASE_ERROR, DELETE_DISABLED_NO_PERM, DELETE_SUBDOMAIN_NO_PERM, UNDELETE_DISABLED_NO_PERM};
use crate::rocket::response::Return;
use crate::rocket::auth::session::Session;
use crate::rocket::template::authenticated::domain_base::DomainBase;

mod private {
    use std::collections::HashMap;

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct SelectSubdomains {
        pub domains: HashMap<i64, bool>,
    }
}

#[actix_web::post("/admin/<domain>/subdomains/disable")]
pub async fn admin_domain_subdomains_delete(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    data: ::actix_web::web::Form<private::SelectSubdomains>,
) -> Return {
    let session = match &*session_ref {
        None => return unauth(domain).into(),
        Some(v) => v,
    };


    let no_perm = |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: DELETE_SUBDOMAIN_NO_PERM,
    });
    let permissions = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permissions.admin() && !permissions.delete_subdomain(){
        return no_perm(domain.into()).into();
    }

    let db_error = |domain|(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, DomainBase{
        domain,
        content: DATABASE_ERROR,
    });

    let pool = crate::get_db().await;
    let domains = data.into_inner().domains.into_iter().filter_map(|(k, v)|if v {Some(k)} else {None}).collect::<Vec<_>>();
    match sqlx::query!(r#"SELECT disable_subdomain($1, $2) as id"#,
        &domains,
        session.get_user_id()
    ).fetch_all(&pool).await {
        Ok(v) => {
            let domains = HashSet::from_iter(domains);
            let processed_domains = v.into_iter().filter_map(|v|v.id).collect::<HashSet<_>>();
            if domains.len() != processed_domains.len() {
                let not_recovered = domains.difference(&processed_domains).collect::<Vec<_>>();
                let extra_recovered = processed_domains.difference(&domains).collect::<Vec<_>>();
                if not_recovered.len() > 0 {
                    log::warn!("Error disabling subdomains. User {} tried disabling domains {not_recovered:?}, for which he didn't have permission", session.get_user_id());
                }
                if extra_recovered.len() > 0 {
                    log::error!("Error disabling subdomains. User {} tried disabling domains {domains:?}, but we additionally recovered {extra_recovered:?} ", session.get_user_id());
                }
            }
            Return::redirect_to(format!("/admin/{domain}/subdomains"))
        },
        Err(err) => {
            log::error!("Error deleting subdomain: {err}");
            db_error(domain.into()).into()
        }
    }

}
#[actix_web::post("/admin/<domain>/subdomains/delete")]
pub async fn admin_domain_subdomains_delete_post(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    data: ::actix_web::web::Form<private::SelectSubdomains>,
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
    if !permissions.admin() && !(permissions.delete_disabled() && permissions.list_subdomain()) {
        return no_perm(domain.into()).into();
    }

    let db_error = |domain|(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, DomainBase{
        domain,
        content: DATABASE_ERROR,
    });

    let pool = crate::get_db().await;
    let domains = data.into_inner().domains.into_iter().filter_map(|(k, v)|if v {Some(k)} else {None}).collect::<Vec<_>>();
    match sqlx::query!(r#"SELECT delete_subdomain($1, $2) as id"#,
        &domains,
        session.get_user_id()
    ).fetch_all(&pool).await {
        Ok(v) => {
            let domains = HashSet::from_iter(domains);
            let processed_domains = v.into_iter().filter_map(|v|v.id).collect::<HashSet<_>>();
            if domains.len() != processed_domains.len() {
                let not_recovered = domains.difference(&processed_domains).collect::<Vec<_>>();
                let extra_recovered = processed_domains.difference(&domains).collect::<Vec<_>>();
                if not_recovered.len() > 0 {
                    log::warn!("Error deleting subdomains. User {} tried deleting domains {not_recovered:?}, for which he didn't have permission", session.get_user_id());
                }
                if extra_recovered.len() > 0 {
                    log::error!("Error deleting subdomains. User {} tried deleting domains {domains:?}, but we additionally recovered {extra_recovered:?} ", session.get_user_id());
                }
            }
            Return::redirect_to(format!("/admin/{domain}/subdomains"))
        },
        Err(err) => {
            log::error!("Error disabling subdomain: {err}");
            db_error(domain.into()).into()
        }
    }

}
#[actix_web::post("/admin/<domain>/subdomains/recover")]
pub async fn admin_domain_subdomains_recover_post(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    data: ::actix_web::web::Form<private::SelectSubdomains>,
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
    if !permissions.admin() && !(permissions.undelete() && permissions.list_subdomain()) {
        return no_perm(domain.into()).into();
    }

    let db_error = |domain|(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, DomainBase{
        domain,
        content: DATABASE_ERROR,
    });

    let pool = crate::get_db().await;
    let domains = data.into_inner().domains.into_iter().filter_map(|(k, v)|if v {Some(k)} else {None}).collect::<Vec<_>>();
    match sqlx::query!(r#"SELECT recover_subdomain($1, $2) as id"#,
        &domains,
        session.get_user_id()
    ).fetch_all(&pool).await {
        Ok(v) => {
            let domains = HashSet::from_iter(domains);
            let processed_domains = v.into_iter().filter_map(|v|v.id).collect::<HashSet<_>>();
            if domains.len() != processed_domains.len() {
                let not_recovered = domains.difference(&processed_domains).collect::<Vec<_>>();
                let extra_recovered = processed_domains.difference(&domains).collect::<Vec<_>>();
                if not_recovered.len() > 0 {
                    log::warn!("Error recovering subdomains. User {} tried recovering domains {not_recovered:?}, for which he didn't have permission", session.get_user_id());
                }
                if extra_recovered.len() > 0 {
                    log::error!("Error recovering subdomains. User {} tried recovering domains {domains:?}, but we additionally recovered {extra_recovered:?} ", session.get_user_id());
                }
            }
            Return::redirect_to(format!("/admin/{domain}/subdomains"))
        }
        Err(err) => {
            log::error!("Error recovering subdomain: {err}");
            db_error(domain.into()).into()
        }
    }

}
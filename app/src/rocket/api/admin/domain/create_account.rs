use crate::rocket::response::Return;
use crate::rocket::auth::check_password::get_password_hash;
use crate::rocket::content::admin::domain::{accounts::admin_domain_accounts_get_impl, unauth};
use crate::rocket::messages::{ACCOUNT_INVALID_CHARS, CREATE_ACCOUNT_NO_PERM, DATABASE_ERROR, DATABASE_PERMISSION_ERROR};
use crate::rocket::auth::session::Session;
use crate::rocket::template::authenticated::domain_base::DomainBase;

mod private{
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct CreateAccount{
        pub email: String,
        pub password: String,
    }
}

#[actix_web::post("/admin/<domain>/accounts/create")]
pub async fn create_account(
    session_ref: actix_web::web::ReqData<Option<Session>>,
    domain: String,
    data: actix_web::web::Form<private::CreateAccount>
) -> Return {
    let session = match &*session_ref {
        None => return unauth(domain).into(),
        Some(v) => v,
    };

    //okay: ()*,-.[]_
    if !data.email.is_ascii() && data.email.chars().any(|v|
        v == ' ' || v == '!' || v == '"' || v == '#' || v == '$' || v == '%' || v == '&' || v == '\'' ||
        v == '+' || v == '/' ||
        v == '@' || v == '?' || v == '<' || v == '=' || v == '>' || v == ';' || v == ':' ||
        v == '`' || v == '^' || v == '\\' ||
        v == '{' || v == '|' || v == '}' || v == '~' ||
        v == char::from(177) //177 = Delete
    ) {
        return (actix_web::http::StatusCode::BAD_REQUEST, DomainBase{
            domain: domain.into(),
            content: ACCOUNT_INVALID_CHARS,
        }).into();
    }


    let no_perm = |domain|(actix_web::http::StatusCode::FORBIDDEN, DomainBase{
        domain,
        content: CREATE_ACCOUNT_NO_PERM,
    });
    let permission = match session.get_permissions().get(&domain) {
        None => return no_perm(domain.into()).into(),
        Some(v) => v,
    };
    if !permission.admin() && !permission.create_accounts() {
        return no_perm(domain.into()).into();
    }

    let pool = crate::get_db().await;
    let mut transaction = match pool.begin().await {
        Ok(v) => v,
        Err(err) => {
            log::error!("Error beginning transaction: {err}");
            return admin_domain_accounts_get_impl(&*session_ref, domain, Some(DATABASE_ERROR)).await;
        }
    };
    let data = data.into_inner();
    let hash = match get_password_hash(data.password).await {
        Err(err) =>  {
            log::error!("Error getting password hash: {err}");
            return admin_domain_accounts_get_impl(&*session_ref, domain, Some("There was an error setting the account Password."))
                .await
                .override_status(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        },
        Ok(v) => v,
    };
    match sqlx::query!("SELECT insert_new_account($1, $2, $3, '{ARGON2ID}', $4) as id", permission.domain_id(), data.email, hash, session.get_user_id())
        .fetch_optional(&mut *transaction).await.map(|v|v.map(|v|v.id).flatten()) {
        Ok(Some(v)) => v,
        Ok(None) => {
            log::error!("Error creating account: DB permission check failed");
            return admin_domain_accounts_get_impl(&*session_ref, domain, Some(DATABASE_PERMISSION_ERROR))
                .await
                .override_status(actix_web::http::StatusCode::FORBIDDEN);
        },
        Err(err) => {
            log::error!("Error creating account: {err}");
            return admin_domain_accounts_get_impl(&*session_ref, domain, Some(DATABASE_ERROR))
                .await
                .override_status(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    match transaction.commit().await {
        Ok(()) => {},
        Err(err) => {
            log::error!("Error commiting account: {err}");
            return admin_domain_accounts_get_impl(&*session_ref, domain, Some(DATABASE_ERROR))
                .await
                .override_status(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    Return::redirect_to(format!("/admin/{domain}/accounts"))
}
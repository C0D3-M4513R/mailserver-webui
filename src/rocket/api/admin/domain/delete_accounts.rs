use std::borrow::Cow;
use crate::rocket::messages::{DELETE_ACCOUNT_NO_PERM, DATABASE_ERROR, INVALID_CONTENT_TYPE};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::session::Session;

mod private {
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(tag = "v")]
    pub enum DeleteAccounts{
        V1(DeleteAccountsV1),
    }

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct DeleteAccountsV1 {
        pub accounts: Vec<i32>,
    }
}

pub const DELETE_ACCOUNTS_MEDIA_TYPE: rocket::http::MediaType = rocket::http::MediaType::const_new(
    "application",
    "vnd.com.c0d3m4513r.mail-admin_delete_account.v1+json",
    &[]
);
pub const DELETE_ACCOUNTS_CONTENT_TYPE: rocket::http::ContentType = rocket::http::ContentType(DELETE_ACCOUNTS_MEDIA_TYPE);

#[rocket::delete("/admin/<domain>/accounts", data="<data>")]
pub async fn admin_domain_accounts_delete(
    content_type: &'_ rocket::http::ContentType,
    session: Session,
    domain: &str,
    data: ::rocket::serde::json::Json<private::DeleteAccounts>
) -> Return {
    if content_type != &DELETE_ACCOUNTS_CONTENT_TYPE {
        return Return::Json((rocket::http::Status::UnsupportedMediaType, TypedContent{
            content_type: super::super::super::error::JSON_ERROR_CONTENT_TYPE,
            content: rocket::serde::json::json!({
                "message": INVALID_CONTENT_TYPE,
            }),
        }));
    }

    const NO_PERM:Return = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: super::super::super::error::JSON_ERROR_CONTENT_TYPE,
        content: Cow::Borrowed(const_format::formatcp!(r#"{{"message": "{DELETE_ACCOUNT_NO_PERM}"}}"#)),
    }));

    let permissions = match session.get_permissions().get(domain) {
        None => return NO_PERM,
        Some(v) => v,
    };

    if !permissions.get_modify_accounts(){
        return NO_PERM;
    }

    const DB_ERROR:Return = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: super::super::super::error::JSON_ERROR_CONTENT_TYPE,
        content: Cow::Borrowed(const_format::formatcp!(r#"{{"message": "{DATABASE_ERROR}"}}"#)),
    }));

    let db = crate::get_mysql().await;
    match &*data {
        private::DeleteAccounts::V1(data) => {
            match sqlx::query!(
                r#"
                DELETE FROM virtual_users users
                   WHERE users.id = ANY($1) AND users.domain_id IN (SELECT id FROM virtual_domains WHERE name = $2)
                "#,
                &data.accounts,
                domain
            ).execute(db).await {
                Ok(_) => Return::Status(rocket::http::Status::NoContent),
                Err(err) => {
                    log::error!("Error deleting accounts: {err}");
                    DB_ERROR
                }
            }
        }
    }

}
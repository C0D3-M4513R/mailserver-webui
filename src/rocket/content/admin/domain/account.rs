use std::borrow::Cow;
use crate::rocket::content::admin::domain::{domain_linklist, template, unauth_error};
use crate::rocket::messages::DATABASE_ERROR;
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::session::Session;

#[rocket::get("/admin/<domain>/accounts/<user_id>")]
pub async fn admin_domain_account_get(session: Option<Session>, domain: &str, user_id:i32) -> Return {
    admin_domain_account_get_impl(session, domain, user_id, None).await
}

pub(in crate::rocket) async fn admin_domain_account_get_impl(session: Option<Session>, domain: &str, user_id:i32, error: Option<&str>) -> Return {
    let session = match session {
        None => return Return::Redirect(rocket::response::Redirect::to(rocket::uri!("/"))),
        Some(v) => v,
    };
    let unauth_error = unauth_error(domain);
    let permissions = match session.get_permissions().get(domain) {
        None => return Return::Content((rocket::http::Status::Forbidden, TypedContent{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(unauth_error),
        })),
        Some(v) => v,
    };

    if !permissions.get_admin() {
        if
        !permissions.get_web_login() ||
            !permissions.get_view_domain() ||
            !permissions.get_list_accounts()
        {
            return Return::Content((rocket::http::Status::Forbidden, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(unauth_error),
            }));
        }
    }

    let db = crate::get_mysql().await;
    let account = match sqlx::query!(r#"
SELECT
    users.id,
    users.email,
    target_perms.*
FROM virtual_users users
JOIN flattened_web_domain_permissions target_perms ON target_perms.user_id = users.id
WHERE users.id = $1 AND target_perms.domain_id = $2
"#, user_id, permissions.get_domain_id())
        .fetch_one(db)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            #[cfg(debug_assertions)]
            log::error!("Error fetching accounts: {err}");
            return Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(template(domain, DATABASE_ERROR)),
            }));
        }
    };

    let modify_account = if permissions.get_modify_accounts() {
        ""
    } else {
        "disabled"
    };

    let email = &account.email;
    let account_info = format!(r#"
<h2>Account Information:</h2>
    <h3>Be VERY careful Changing the email. Any content in that Account will (currently) not transfer over to the new name.</h3>
    <p>You should prefer using an alias, and just using the alias to send. Theoretically changing the email to something and then changing it back should work though (It is not guaranteed to though).</p>
<form method="POST" action="{user_id}/email">
    <input type="hidden" name="_method" value="PUT" />
    <label>Email: <a><input type="text" name="email" value="{email}" {modify_account} />@{domain}</a></label>
    <input type="submit" name="action" value="Update Email" {modify_account}/>
</form>
<form method="POST" action="{user_id}/password">
    <input type="hidden" name="_method" value="PUT" />
    <label>Password: <input type="password" name="password" {modify_account} /></label>
    <input type="submit" value="Update Password" {modify_account}/>
</form>
    "#);

    let header = domain_linklist(&session, domain);
    let error = error.unwrap_or("");
    Return::Content((rocket::http::Status::Ok, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, format!(r#"
    {header}
<div id="account-mod-error">{error}</div>
{account_info}
{list_permissions}
        "#).as_str())),
    }))
}
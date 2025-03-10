use std::borrow::Cow;
use crate::rocket::content::admin::domain::{domain_linklist, template, unauth_error};
use crate::rocket::content::admin::domain::permissions::format_value;
use crate::rocket::messages::{DATABASE_ERROR, LIST_ACCOUNT_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::Session;

#[rocket::get("/admin/<domain>/accounts/<user_id>")]
pub async fn admin_domain_account_get(session: Option<Session>, domain: &str, user_id:i64) -> Return {
    admin_domain_account_get_impl(session, domain, user_id, None).await
}

pub(in crate::rocket) async fn admin_domain_account_get_impl(session: Option<Session>, domain: &str, user_id:i64, error: Option<&str>) -> Return {
    let session = match session {
        None => return Return::Content((rocket::http::Status::Forbidden, TypedContent{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(unauth_error(domain)),
        })),
        Some(v) => v,
    };
    let no_perm = Return::Content((rocket::http::Status::Forbidden, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, LIST_ACCOUNT_NO_PERM)),
    }));
    let permissions = match session.get_permissions().get(domain) {
        None => return no_perm,
        Some(v) => v,
    };
    if !permissions.admin() {
        if
            !permissions.view_domain() ||
            !permissions.list_accounts()
        {
            return no_perm;
        }
    }

    let db = crate::get_mysql().await;
    let account = match sqlx::query!(r#"
SELECT
    users.email AS "email!",
    COALESCE(user_perm.self_change_password, true) AS "self_change_password!",
    target_perms.admin,
    target_perms.view_domain,
    target_perms.modify_domain,
    target_perms.list_subdomain,
    target_perms.create_subdomain,
    target_perms.delete_subdomain,
    target_perms.list_accounts,
    target_perms.create_accounts,
    target_perms.modify_accounts,
    target_perms.delete_accounts,
    target_perms.create_alias,
    target_perms.modify_alias,
    target_perms.list_permissions,
    target_perms.manage_permissions
FROM virtual_users users
LEFT JOIN web_domain_permissions target_perms ON target_perms.user_id = users.id AND target_perms.domain_id = $2
LEFT JOIN user_permission user_perm ON users.id = user_perm.id
WHERE users.id = $1
"#, user_id, permissions.domain_id())
        .fetch_one(db)
        .await
    {
        Ok(v) => v,
        Err(err) => {

            log::error!("Error fetching accounts: {err}");
            return Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(template(domain, DATABASE_ERROR)),
            }));
        }
    };

    let modify_account = if permissions.admin() || permissions.modify_accounts() {
        ""
    } else {
        "disabled"
    };

    let delete = if permissions.admin() || permissions.delete_accounts() {
        format!(r#"<form method="POST"><input type="hidden" name="_method" value="DELETE"><input type="submit" value="Delete Account"></form>"#)
    } else {
        String::new()
    };

    let self_change_password = if account.self_change_password {
        "checked"
    } else {
        ""
    };

    let email = &account.email;
    let account_info = format!(r#"
<h2>Account Information:</h2>
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
<form method="Post" action="{user_id}/user_permission">
    <input type="hidden" name="_method" value="PUT" />
    <label>Allow user to Change their Password themselves: <input type="checkbox" name="self_change_password" {self_change_password} {modify_account} /></label>
    <input type="submit" value="Update User Permission" {modify_account}/>
</form>
{delete}
    "#);

    let domain_id = permissions.domain_id();
    let list_permissions = if permissions.admin() || permissions.list_permissions() {
        let p_admin = permissions.admin();
        let p_manage_perm = permissions.manage_permissions();

        let admin = format_value(               "Admin: ",                  "admin",                account.admin,               p_manage_perm && (p_admin || permissions.admin()));
        let view_domain = format_value(         "View Domain: ",            "view_domain",          account.view_domain,         p_manage_perm && (p_admin || permissions.view_domain()));
        let modify_domain = format_value(         "Modify Domain: ",            "modify_domain",    account.modify_domain,         p_manage_perm && (p_admin || permissions.modify_domain()));
        let list_subdomain = format_value(      "List Subdomain: ",         "list_subdomain",       account.list_subdomain,      p_manage_perm && (p_admin || permissions.list_subdomain()));
        let create_subdomain = format_value(    "Create Subdomain: ",       "create_subdomain",     account.create_subdomain,    p_manage_perm && (p_admin || permissions.create_subdomain()));
        let delete_subdomain = format_value(    "Delete Subdomain: ",       "delete_subdomain",     account.delete_subdomain,    p_manage_perm && (p_admin || permissions.delete_subdomain()));
        let list_accounts = format_value(       "List Accounts: ",          "list_accounts",        account.list_accounts,       p_manage_perm && (p_admin || permissions.list_accounts()));
        let create_accounts = format_value(     "Create Accounts: ",        "create_accounts",      account.create_accounts,     p_manage_perm && (p_admin || permissions.create_accounts()));
        let modify_accounts = format_value(     "Modify Accounts: ",        "modify_accounts",      account.modify_accounts,     p_manage_perm && (p_admin || permissions.modify_accounts()));
        let delete_accounts = format_value(     "Delete Accounts: ",        "delete_accounts",      account.delete_accounts,     p_manage_perm && (p_admin || permissions.delete_accounts()));
        let create_alias = format_value(        "Create Alias: ",           "create_alias",         account.create_alias,        p_manage_perm && (p_admin || permissions.create_alias()));
        let modify_alias = format_value(        "Modify Alias: ",           "modify_alias",         account.modify_alias,        p_manage_perm && (p_admin || permissions.modify_alias()));
        let list_permissions = format_value(    "List Permissions: ",       "list_permissions",     account.list_permissions,    p_manage_perm && (p_admin || permissions.list_permissions()));
        let manage_permissions = format_value(  "Manage Permissions: ",     "manage_permissions",   account.manage_permissions,  p_manage_perm && (p_admin || permissions.manage_permissions()));
        format!(r#"
<h2>Permissions:</h2>
<p>Notice: Without List permissions, Modification permissions are useless. Also, Modification permission imply Delete permissions</p>
<form method="POST" action="{user_id}/permissions" onsubmit="(event)=>event.target.reset()">
    <input type="hidden" name="_method" value="PUT"/>
    <input type="hidden" name="domain_id" value="{domain_id}"/>
    {admin} This Permission overrides everything else (except manage permissions), if set.<br/>
    {view_domain}<br/>
    {modify_domain}<br/>
    {list_subdomain}<br/>
    {create_subdomain}<br/>
    {delete_subdomain}<br/>
    {list_accounts}<br/>
    {create_accounts}<br/>
    {modify_accounts}<br/>
    {delete_accounts}<br/>
    {create_alias}<br/>
    {modify_alias}<br/>
    {list_permissions}<br/>
    {manage_permissions}<br/>
    <input type="submit" value="Save Changes"/>
</form>
        "#)
    } else {
        String::new()
    };

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
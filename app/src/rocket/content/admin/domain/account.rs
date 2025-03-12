use std::borrow::Cow;
use crate::rocket::content::admin::domain::{domain_linklist, template, unauth_error};
use crate::rocket::content::admin::domain::permissions::format_value;
use crate::rocket::messages::{DATABASE_ERROR, LIST_ACCOUNT_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::Session;

#[rocket::get("/admin/<domain>/accounts/<user_name>")]
pub async fn admin_domain_account_get(session: Option<Session>, domain: &str, user_name:&str) -> Return {
    admin_domain_account_get_impl(session, domain, user_name, None).await
}

pub(in crate::rocket) async fn admin_domain_account_get_impl(session: Option<Session>, domain: &str, user_name:&str, error: Option<&str>) -> Return {
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
    users.id AS "id!",
    COALESCE(user_perm.self_change_password, true) AS "self_change_password!",
    target_perms.admin, flat_perms.admin as "current_admin!",
    target_perms.view_domain, flat_perms.view_domain as "current_view_domain!",
    target_perms.modify_domain, flat_perms.modify_domain as "current_modify_domain!",
    target_perms.list_subdomain, flat_perms.list_subdomain as "current_list_subdomain!",
    target_perms.create_subdomain, flat_perms.create_subdomain as "current_create_subdomain!",
    target_perms.delete_subdomain, flat_perms.delete_subdomain as "current_delete_subdomain!",
    target_perms.list_accounts, flat_perms.list_accounts as "current_list_accounts!",
    target_perms.create_accounts, flat_perms.create_accounts as "current_create_accounts!",
    target_perms.modify_accounts, flat_perms.modify_accounts as "current_modify_accounts!",
    target_perms.delete_accounts, flat_perms.delete_accounts as "current_delete_accounts!",
    target_perms.list_alias, flat_perms.list_alias as "current_list_alias!",
    target_perms.create_alias, flat_perms.create_alias as "current_create_alias!",
    target_perms.delete_alias, flat_perms.delete_alias as "current_delete_alias!",
    target_perms.list_permissions, flat_perms.list_permissions as "current_list_permissions!",
    target_perms.manage_permissions, flat_perms.manage_permissions as "current_manage_permissions!"
FROM virtual_users users
LEFT JOIN web_domain_permissions target_perms ON target_perms.user_id = users.id AND target_perms.domain_id = users.domain_id
LEFT JOIN user_permission user_perm ON users.id = user_perm.id
JOIN flattened_web_domain_permissions flat_perms ON flat_perms.domain_id = users.domain_id AND flat_perms.user_id = users.id
WHERE users.email = $1 AND users.domain_id = $2
"#, user_name, permissions.domain_id())
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
        format!(r#"<form method="POST"><input type="hidden" name="_method" value="DELETE"><input type="submit" value="Disable Account"></form>"#)
    } else {
        String::new()
    };

    let self_change_password = if account.self_change_password {
        "checked"
    } else {
        ""
    };

    let user_id = account.id;
    let account_info = format!(r#"
<h2>Account Information:</h2>
<form method="POST" action="{user_name}/email">
    <input type="hidden" name="_method" value="PUT" />
    <label>Email: <a><input type="text" name="email" value="{user_name}" {modify_account} />@{domain}</a></label>
    <input type="submit" name="action" value="Update Email" {modify_account}/>
</form>
<form method="POST" action="{user_name}/password">
    <input type="hidden" name="_method" value="PUT" />
    <label>Password: <input type="password" name="password" {modify_account} /></label>
    <input type="submit" value="Update Password" {modify_account}/>
</form>
<form method="Post" action="{user_name}/user_permission">
    <input type="hidden" name="_method" value="PUT" />
    <label>Allow user to Change their Password themselves: <input type="checkbox" name="self_change_password" {self_change_password} {modify_account} /></label>
    <input type="submit" value="Update User Permission" {modify_account}/>
</form>
{delete}
    "#);

    let aliases = if permissions.admin() || permissions.list_alias() {
        match sqlx::query!(r#"SELECT alias.id as "id!", alias.source || '@' || domains.name as "email!" FROM virtual_aliases alias
    JOIN flattened_domains domains ON domains.id = alias.domain_id
    WHERE destination = $1
    "#, user_id).fetch_all(db).await
        {
            Ok(v) => {
                let delete = if permissions.admin() || permissions.delete_alias() {
                    r#"<input type="hidden" name="_method" value="DELETE"><input type="submit" value="Delete Selected Aliases">"#
                } else {
                    ""
                };
                let aliases = v.into_iter().map(|v| {
                    let email = v.email;
                    let id = v.id;
                    format!(r#"<tr><td><input type="checkbox" name="aliases[{id}]" /></td><td><a>{email}</a></td></tr>"#)
                }).reduce(|a, b| format!("{a}{b}")).unwrap_or_default();
                format!(r#"
                <h2>Aliases pointing to this Account:</h2>
                <form method="POST" action="{user_name}/aliases">
                {delete}
                <table>
                    <tr><th>Selected</th><th>Source</th></tr>
                    {aliases}
                </table></form>
                "#)
            },
            Err(v) => {
                log::error!("Error fetching aliases: {v}");
                const ALIASES_ERR:&str = const_format::concatcp!("<h2>Aliases:</h2><p>", DATABASE_ERROR, "</p>");
                ALIASES_ERR.to_string()
            }
        }
    } else {
        String::new()
    };

    let domain_id = permissions.domain_id();
    let list_permissions = if permissions.admin() || permissions.list_permissions() {
        let p_admin = permissions.admin();
        let p_manage_perm = permissions.manage_permissions();

        let admin = format_value(               "Admin: ",                  format!("users[{user_id}].value.admin"),                account.admin,                  account.current_admin,               p_manage_perm && (p_admin || permissions.admin()));
        let view_domain = format_value(         "View Domain: ",            format!("users[{user_id}].value.view_domain"),          account.view_domain,            account.current_view_domain,         p_manage_perm && (p_admin || permissions.view_domain()));
        let modify_domain = format_value(         "Modify Domain: ",        format!("users[{user_id}].value.modify_domain"),        account.modify_domain,          account.current_modify_domain,         p_manage_perm && (p_admin || permissions.modify_domain()));
        let list_subdomain = format_value(      "List Subdomain: ",         format!("users[{user_id}].value.list_subdomain"),       account.list_subdomain,         account.current_list_subdomain,      p_manage_perm && (p_admin || permissions.list_subdomain()));
        let create_subdomain = format_value(    "Create Subdomain: ",       format!("users[{user_id}].value.create_subdomain"),     account.create_subdomain,       account.current_create_subdomain,    p_manage_perm && (p_admin || permissions.create_subdomain()));
        let delete_subdomain = format_value(    "Delete Subdomain: ",       format!("users[{user_id}].value.delete_subdomain"),     account.delete_subdomain,       account.current_delete_subdomain,    p_manage_perm && (p_admin || permissions.delete_subdomain()));
        let list_accounts = format_value(       "List Accounts: ",          format!("users[{user_id}].value.list_accounts"),        account.list_accounts,          account.current_list_accounts,       p_manage_perm && (p_admin || permissions.list_accounts()));
        let create_accounts = format_value(     "Create Accounts: ",        format!("users[{user_id}].value.create_accounts"),      account.create_accounts,        account.current_create_accounts,     p_manage_perm && (p_admin || permissions.create_accounts()));
        let modify_accounts = format_value(     "Modify Accounts: ",        format!("users[{user_id}].value.modify_accounts"),      account.modify_accounts,        account.current_modify_accounts,     p_manage_perm && (p_admin || permissions.modify_accounts()));
        let delete_accounts = format_value(     "Delete Accounts: ",        format!("users[{user_id}].value.delete_accounts"),      account.delete_accounts,        account.current_delete_accounts,     p_manage_perm && (p_admin || permissions.delete_accounts()));
        let list_alias = format_value(          "List Alias: ",           format!("users[{user_id}].value.list_alias"),             account.list_alias,             account.current_list_alias,          p_manage_perm && (p_admin || permissions.list_alias()));
        let create_alias = format_value(        "Create Alias: ",           format!("users[{user_id}].value.create_alias"),         account.create_alias,           account.current_create_alias,        p_manage_perm && (p_admin || permissions.create_alias()));
        let delete_alias = format_value(        "Delete Alias: ",           format!("users[{user_id}].value.delete_alias"),         account.delete_alias,           account.current_delete_alias,        p_manage_perm && (p_admin || permissions.delete_alias()));
        let list_permissions = format_value(    "List Permissions: ",       format!("users[{user_id}].value.list_permissions"),     account.list_permissions,       account.current_list_permissions,    p_manage_perm && (p_admin || permissions.list_permissions()));
        let manage_permissions = format_value(  "Manage Permissions: ",     format!("users[{user_id}].value.manage_permissions"),   account.manage_permissions,     account.current_manage_permissions,  p_manage_perm && (p_admin || permissions.manage_permissions()));
        format!(r#"
<h2>Permissions:</h2>
<p>Notice: Without List permissions, Modification permissions are useless. Also, Modification permission imply Delete permissions</p>
<form method="POST" action="{user_name}/permissions" onsubmit="(event)=>event.target.reset()">
    <input type="hidden" name="_method" value="PUT"/>
    <input type="hidden" name="users[{user_id}].enabled" value="on"/>
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
    {list_alias}<br/>
    {create_alias}<br/>
    {delete_alias}<br/>
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
{aliases}
{list_permissions}
        "#).as_str())),
    }))
}
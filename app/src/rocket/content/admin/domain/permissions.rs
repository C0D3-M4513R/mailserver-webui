use std::borrow::Cow;
use std::fmt::Display;
use crate::rocket::content::admin::domain::{domain_linklist, template, UNAUTH};
use crate::rocket::messages::{DATABASE_ERROR, LIST_ACCOUNT_NO_PERM};
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::auth::session::Session;
use crate::rocket::template::authenticated::domain_base::DomainBase;

#[rocket::get("/admin/<domain>/permissions")]
pub async fn admin_domain_permissions_get(session: Option<Session>, domain: &str) -> Return {
    admin_domain_permissions_get_impl(session, domain, None).await
}

pub(in crate::rocket) async fn admin_domain_permissions_get_impl(session: Option<Session>, domain: &str, error: Option<&str>) -> Return {
    let session = match session {
        None => return UNAUTH(domain).into(),
        Some(v) => v,
    };
    let no_perm = (rocket::http::Status::Forbidden, DomainBase{
        domain,
        content: LIST_ACCOUNT_NO_PERM,
    });
    let permissions = match session.get_permissions().get(domain) {
        None => return no_perm.into(),
        Some(v) => v,
    };

    if !permissions.admin() {
        if
        !permissions.view_domain() ||
            !permissions.list_accounts()
        {
            return no_perm.into();
        }
    }

    let db = crate::get_db().await;
    let accounts = match sqlx::query!(r#"
SELECT
    user_domain.name as "name!",
    users.email as "email!",
    users.id as "id!",
    users.id = ANY(domains.domain_owner) as "is_owner!",
    perms.admin, COALESCE(flat_perms.admin, false) as "current_admin!",
    perms.view_domain, COALESCE(flat_perms.view_domain, false) as "current_view_domain!",
    perms.modify_domain, COALESCE(flat_perms.modify_domain, false) as "current_modify_domain!",
    perms.list_subdomain, COALESCE(flat_perms.list_subdomain, false) as "current_list_subdomain!",
    perms.create_subdomain, COALESCE(flat_perms.create_subdomain, false) as "current_create_subdomain!",
    perms.delete_subdomain, COALESCE(flat_perms.delete_subdomain, false) as "current_delete_subdomain!",
    perms.list_accounts, COALESCE(flat_perms.list_accounts, false) as "current_list_accounts!",
    perms.create_accounts, COALESCE(flat_perms.create_accounts, false) as "current_create_accounts!",
    perms.modify_accounts, COALESCE(flat_perms.modify_accounts, false) as "current_modify_accounts!",
    perms.delete_accounts, COALESCE(flat_perms.delete_accounts, false) as "current_delete_accounts!",
    perms.list_alias, COALESCE(flat_perms.list_alias, false) as "current_list_alias!",
    perms.create_alias, COALESCE(flat_perms.create_alias, false) as "current_create_alias!",
    perms.delete_alias, COALESCE(flat_perms.delete_alias, false) as "current_delete_alias!",
    perms.list_permissions, COALESCE(flat_perms.list_permissions, false) as "current_list_permissions!",
    perms.manage_permissions, COALESCE(flat_perms.manage_permissions, false) as "current_manage_permissions!"
FROM virtual_domains domains
    JOIN virtual_users users ON users.domain_id = domains.id OR users.domain_id = ANY(domains.super)
    JOIN virtual_domains user_domain ON users.domain_id = user_domain.id
    LEFT JOIN web_domain_permissions perms ON perms.domain_id = domains.id AND perms.user_id = users.id
    LEFT JOIN flattened_web_domain_permissions flat_perms ON cardinality(domains.super) = 0 AND flat_perms.domain_id = domains.super[1] AND flat_perms.user_id = users.id
WHERE domains.id = $1"#, permissions.domain_id())
        .fetch_all(&db)
        .await
    {
        Ok(v) => v.into_iter().map(|v|{
            let name = v.name;
            let user_id = v.id;
            let list_permissions = if permissions.admin() || permissions.list_permissions() {
                let p_admin = permissions.admin();
                let p_manage_perm = permissions.manage_permissions();

                let is_owner = {
                    let checked = if v.is_owner { "checked" } else { "" };
                    format!(r#"<input type="checkbox" {checked} disabled />"#)
                };
                let admin = format_value(               "",                  format!("users[{user_id}].value.admin"),              v.admin, v.current_admin,               p_manage_perm && (p_admin || permissions.admin()));
                let view_domain = format_value(         "",            format!("users[{user_id}].value.view_domain"),        v.view_domain, v.current_view_domain,         p_manage_perm && (p_admin || permissions.view_domain()));
                let modify_domain = format_value(         "",            format!("users[{user_id}].value.modify_domain"),  v.modify_domain, v.current_modify_domain,       p_manage_perm && (p_admin || permissions.modify_domain()));
                let list_subdomain = format_value(      "",         format!("users[{user_id}].value.list_subdomain"),     v.list_subdomain, v.current_list_subdomain,      p_manage_perm && (p_admin || permissions.list_subdomain()));
                let create_subdomain = format_value(    "",       format!("users[{user_id}].value.create_subdomain"),   v.create_subdomain, v.current_create_subdomain,    p_manage_perm && (p_admin || permissions.create_subdomain()));
                let delete_subdomain = format_value(    "",       format!("users[{user_id}].value.delete_subdomain"),   v.delete_subdomain, v.current_delete_subdomain,    p_manage_perm && (p_admin || permissions.delete_subdomain()));
                let list_accounts = format_value(       "",          format!("users[{user_id}].value.list_accounts"),      v.list_accounts, v.current_list_accounts,       p_manage_perm && (p_admin || permissions.list_accounts()));
                let create_accounts = format_value(     "",        format!("users[{user_id}].value.create_accounts"),    v.create_accounts, v.current_create_accounts,     p_manage_perm && (p_admin || permissions.create_accounts()));
                let modify_accounts = format_value(     "",        format!("users[{user_id}].value.modify_accounts"),    v.modify_accounts, v.current_modify_accounts,     p_manage_perm && (p_admin || permissions.modify_accounts()));
                let delete_accounts = format_value(     "",        format!("users[{user_id}].value.delete_accounts"),    v.delete_accounts, v.current_delete_accounts,     p_manage_perm && (p_admin || permissions.delete_accounts()));
                let list_alias = format_value(        "",           format!("users[{user_id}].value.list_alias"),             v.list_alias, v.current_list_alias,          p_manage_perm && (p_admin || permissions.list_alias()));
                let create_alias = format_value(        "",           format!("users[{user_id}].value.create_alias"),       v.create_alias, v.current_create_alias,        p_manage_perm && (p_admin || permissions.create_alias()));
                let delete_alias = format_value(        "",           format!("users[{user_id}].value.delete_alias"),       v.delete_alias, v.current_delete_alias,        p_manage_perm && (p_admin || permissions.delete_alias()));
                let list_permissions = format_value(    "",       format!("users[{user_id}].value.list_permissions"),   v.list_permissions, v.current_list_permissions,    p_manage_perm && (p_admin || permissions.list_permissions()));
                let manage_permissions = format_value(  "",     format!("users[{user_id}].value.manage_permissions"), v.manage_permissions, v.current_manage_permissions,  p_manage_perm && (p_admin || permissions.manage_permissions()));
                format!(r#"
    <td>{is_owner}</td>
    <td>{admin}</td>
    <td>{view_domain}</td>
    <td>{modify_domain}</td>
    <td>{list_subdomain}</td>
    <td>{create_subdomain}</td>
    <td>{delete_subdomain}</td>
    <td>{list_accounts}</td>
    <td>{create_accounts}</td>
    <td>{modify_accounts}</td>
    <td>{delete_accounts}</td>
    <td>{list_alias}</td>
    <td>{create_alias}</td>
    <td>{delete_alias}</td>
    <td>{list_permissions}</td>
    <td>{manage_permissions}</td>
                "#)
            } else {
                String::new()
            };
            let email = v.email;

            format!(r#"<tr><td><input class="account-select" type="checkbox" name="users[{user_id}].enabled" /></td><td>{email}@{name}</td>{list_permissions}</tr>"#)
        }).fold(String::new(), |a,b|format!("{a}{b}")),
        Err(err) => {

            log::error!("Error fetching accounts: {err}");
            return (rocket::http::Status::InternalServerError, DomainBase{
                domain,
                content: DATABASE_ERROR,
            }).into();
        }
    };

    let update_permissions = if permissions.admin() || permissions.manage_permissions(){
        r#"<input type="hidden" name="_method" value="PUT" /><input type="submit" value="Update Selected Permissions" />"#
    } else {
        ""
    };
    let header = domain_linklist(&session, domain);
    let error = error.unwrap_or("");
    Return::Content((rocket::http::Status::Ok, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, format!(r#"
    {header}
<div id="account-mod-error">{error}</div>
<h2>Permissions: </h2>
<p>Notice: Without List permissions, Modification permissions are useless. Also, Modification permission imply Delete permissions</p>
<p>Inherited permissions means, that if the user has a permission defined on a parent domain, it will be inherited to this domain. Inherited permissions usually means false.</p>
<p>Owners bypass all permission checks.</p>
<form method="POST" action="/api/admin/domain/{domain}/permissions">
{update_permissions}
    <table>
        <tr>
            <th>Selected</th>
            <th>Email</th>
            <th>Is Owner</th>
            <th>Admin</th>
            <th>View Domain</th>
            <th>Modify Domain</th>
            <th>List Subdomain</th>
            <th>Create Subdomain</th>
            <th>Delete Subdomain</th>
            <th>List Accounts</th>
            <th>Create Accounts</th>
            <th>Modify Accounts</th>
            <th>Delete Accounts</th>
            <th>List Alias</th>
            <th>Create Alias</th>
            <th>Delete Alias</th>
            <th>List Permissions:</th>
            <th>Manage Permissions</th>
        </tr>
        {accounts}
    </table>
</form>
        "#).as_str())),
    }))
}

pub fn format_value(display: impl Display, name: impl Display, value: Option<bool>, current: bool, enabled: bool) -> String {
    let v_value = match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    };
    let extra_disabled = if enabled { String::new() } else { format!(r#"<input type="hidden" name="{name}" value="{v_value}"/>"#) };
    let enabled = if enabled { "" } else { "disabled" };
    const SELECTED:&str = r#"selected="selected""#;
    let (v_true, v_false, v_null) = match value {
        Some(true) => (SELECTED, "", ""),
        Some(false) => ("", SELECTED, ""),
        None => ("", "", SELECTED),
    };
    format!(r#"{extra_disabled}<label>{display}<select name="{name}" {enabled} >
    <option value="true" {v_true}>True</option>
    <option value="false" {v_false}>False</option>
    <option value="null" {v_null}>Inherited ({current})</option>
</select></label>
            "#)
}
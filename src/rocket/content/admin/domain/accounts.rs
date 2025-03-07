use std::borrow::Cow;
use crate::rocket::content::admin::domain::{domain_linklist, template, unauth_error};
use crate::rocket::messages::DATABASE_ERROR;
use crate::rocket::response::{Return, TypedContent};
use crate::rocket::session::Session;

#[rocket::get("/admin/<domain>/accounts")]
pub async fn admin_domain_accounts_get(session: Option<Session>, domain: &str) -> Return {
    admin_domain_accounts_get_impl(session, domain, None).await
}

pub(in crate::rocket) async fn admin_domain_accounts_get_impl(session: Option<Session>, domain: &str, error: Option<&str>) -> Return {
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
    let accounts = match sqlx::query!(r#"
SELECT
    users.id,
    users.email
FROM virtual_users users
WHERE users.domain_id = $1"#, permissions.get_domain_id())
        .fetch_all(db)
        .await
    {
        Ok(v) => v.into_iter().map(|v|{
            let email = v.email;
            let full_email = format!("{email}@{domain}");
            let modify = if permissions.get_modify_accounts() {
                format!(r#"<a href="/admin/{domain}/accounts/{}">Modify</a>"#, v.id)
            } else {
                String::new()
            };
            let delete = if permissions.get_modify_accounts() {
                format!(r#"<a href="javascript:deleteAccount({{v:'V1', accounts: [{}]}})">Delete</a>"#, v.id)
            } else {
                String::new()
            };

            format!(r#"<tr><td><input class="account-select" type="checkbox" /></td><td>{full_email}</td><td>{modify} {delete}</td></tr>"#)
        }).fold(String::new(), |a,b|format!("{a}{b}")),
        Err(err) => {
            #[cfg(debug_assertions)]
            log::error!("Error fetching accounts: {err}");
            return Return::Content((rocket::http::Status::InternalServerError, TypedContent{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(template(domain, DATABASE_ERROR)),
            }));
        }
    };

    let new_account = if permissions.get_create_accounts() {
        format!(r#"<h2>Create new Account:</h2>
<form method="POST">
    <input type="hidden" name="_method" value="PUT" />
    <label>Email: <a></a><input type="text" name="email" />@{domain}</a></label><br>
    <label>Password: <input type="password" name="password" /></label><br>
    <input type="submit" value="Add Account" />
</form>"#)
    } else {
        String::new()
    };

    let header = domain_linklist(&session, domain);
    let error = error.unwrap_or("");
    Return::Content((rocket::http::Status::Ok, TypedContent{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(template(domain, format!(r#"
    {header}
<script>
async function deleteAccount(body) {{
    let response = await fetch(`/admin/{domain}/accounts`, {{
        method: 'DELETE',
        headers: {{
            'Accept': ['{JSON_ERROR_CONTENT_TYPE}'],
            'Content-Type': '{DELETE_ACCOUNTS_CONTENT_TYPE}',
        }},
        body: JSON.stringify(body),
    }});
    if (response.ok) {{
        window.location.reload();
    }} else {{
        let json = await response.json();
        document.getElementById('account-mod-error').innerHTML = json.message;
    }}
}}
</script>
<div id="account-mod-error">{error}</div>
{new_account}
<h2>Existing Accounts:</h2>
    <table>
        <tr>
            <th></th>
            <th>Email</th>
            <th>Actions</th>
        </tr>
        {accounts}
    </table>
        "#).as_str())),
    }))
}
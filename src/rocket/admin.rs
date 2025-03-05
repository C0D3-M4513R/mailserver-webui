use std::borrow::Cow;
mod private {
    use std::borrow::Cow;

    #[derive(rocket::response::Responder)]
    pub enum AdminReturn {
        DomainGet((rocket::http::Status, AdminDomainGet)),
        Redirect(rocket::response::Redirect),
    }

    #[derive(rocket::response::Responder)]
    pub struct AdminDomainGet {
        pub(super) content: Cow<'static, str>,
        pub(super) content_type: rocket::http::ContentType,
    }
}

const LOGOUT:&str = r#"
    <form action="/logout" method="POST">
        <input type="submit" value="Logout"></input>
    </form>
"#;

#[rocket::get("/admin")]
pub async fn admin_get(session: Option<super::session::Session>) -> private::AdminReturn {
    let session = match session {
        None => return private::AdminReturn::Redirect(rocket::response::Redirect::to(rocket::uri!("/"))),
        Some(v) => v,
    };

    let mut domain_list = String::new();
    let mut permissions = session.get_permissions().iter().collect::<Vec<_>>();
    permissions.sort_by_key(|(k, _)| *k);
    for (domain, permissions) in permissions {
        if !permissions.get_web_login() || !permissions.get_view_domain() {
            continue;
        }
        domain_list.push_str(&format!(r#"<li><a href="/admin/{domain}/view">{domain}</a></li>"#));
    }

    private::AdminReturn::DomainGet((rocket::http::Status::Ok, private::AdminDomainGet{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Admin</title>
</head>
<body>
    <h1>Admin</h1>
    {LOGOUT}

    <p>Welcome to the admin page</p>
    <p>Managable Domains:</p>
    <ul>{domain_list}</ul>
</body>
</html>
        "#))
    }))
}

#[rocket::get("/admin/<domain>/view")]
pub async fn admin_domain_get(session: Option<super::session::Session>, domain: &str) -> private::AdminReturn {
    let session = match session {
        None => return private::AdminReturn::Redirect(rocket::response::Redirect::to(rocket::uri!("/"))),
        Some(v) => v,
    };
    let unauth_error = format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <title>{domain}'s Mail-Admin-Panel</title>
</head>
<body>
    <h1>{domain}'s Mail-Admin-Panel</h1>
    {LOGOUT}
    <p>Welcome to the admin page</p>
    <p>You are unable to access the Admin-Panel for the domain {domain}.</p>
</body>
</html>
        "#);
    let permissions = match session.get_permissions().get(domain) {
        None => return private::AdminReturn::DomainGet((rocket::http::Status::Forbidden, private::AdminDomainGet{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(unauth_error),
        })),
        Some(v) => v,
    };

    if !permissions.get_web_login() || !permissions.get_view_domain() {
        return private::AdminReturn::DomainGet((rocket::http::Status::Forbidden, private::AdminDomainGet{
            content_type: rocket::http::ContentType::HTML,
            content: Cow::Owned(unauth_error),
        }));
    }

    private::AdminReturn::DomainGet((rocket::http::Status::Ok, private::AdminDomainGet{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <title>{domain}'s Mail-Admin-Panel</title>
</head>
<body>
    <h1>{domain}'s Mail-Admin-Panel</h1>
    {LOGOUT}
    <p>Welcome to the admin page</p>
    <p>Content could be here.</p>
</body>
</html>
        "#)),
    }))
}

#[rocket::get("/admin/<domain>/accounts")]
pub async fn admin_domain_accounts(session: Option<super::session::Session>, domain: &str) -> private::AdminReturn {
    let session = match session {
        None => return private::AdminReturn::Redirect(rocket::response::Redirect::to(rocket::uri!("/"))),
        Some(v) => v,
    };
    let unauth_error = format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <title>{domain}'s Mail-Admin-Panel</title>
</head>
<body>
    <h1>{domain}'s Mail-Admin-Panel</h1>
    {LOGOUT}
    <p>Welcome to the admin page</p>
    <p>You are unable to access the Admin-Panel for the domain {domain}.</p>
</body>
</html>
        "#);
    let permissions = match session.get_permissions().get(domain) {
        None => return private::AdminReturn::DomainGet((rocket::http::Status::Forbidden, private::AdminDomainGet{
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
            return private::AdminReturn::DomainGet((rocket::http::Status::Forbidden, private::AdminDomainGet{
                content_type: rocket::http::ContentType::HTML,
                content: Cow::Owned(unauth_error),
            }));
        }
    }

    private::AdminReturn::DomainGet((rocket::http::Status::Ok, private::AdminDomainGet{
        content_type: rocket::http::ContentType::HTML,
        content: Cow::Owned(format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <title>{domain}'s Mail-Admin-Panel</title>
</head>
<body>
    <h1>{domain}'s Mail-Admin-Panel</h1>
    {LOGOUT}
    <p>Welcome to the admin page</p>
    <p>Content could be here.</p>
</body>
</html>
        "#)),
    }))
}
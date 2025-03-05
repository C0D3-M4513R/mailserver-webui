const HEAD:&str = r#"<!Doctype html>
<html lang="en">
    <head>
        <title>Mailserver Admin</title>
    </head>
    <body>
        <h1>Mailserver Admin</h1>"#;
const TAIL:&str = r#"        <form method="POST">
            <label>E-Mail: <input type="email" name="email"/></label>
            <label>Password: <input type="password" name="password"/></label>
            <label>Submit: <input type="submit"/></label>
        </form>
    </body>
</html>"#;


#[rocket::get("/")]
pub fn index_get(session: Option<super::session::Session>) -> private::IndexPostReturn {
    match session {
        None => private::IndexPostReturn::Html(rocket::response::content::RawHtml(const_format::concatcp!(HEAD, TAIL))),
        Some(_) => private::IndexPostReturn::Redirect(rocket::response::Redirect::to(rocket::uri!("/admin")))
    }
}


mod private {
    #[derive(rocket::form::FromForm)]
    pub struct Login<'r> {
        pub(super) email: &'r str,
        pub(super) password: &'r str,
    }
    #[derive(rocket::response::Responder)]
    pub enum IndexPostReturn {
        Html(rocket::response::content::RawHtml<&'static str>),
        Redirect(rocket::response::Redirect),
    }
}

#[rocket::post("/", data = "<login>")]
pub async fn index_post(cookies: &rocket::http::CookieJar<'_>, login: rocket::form::Form<private::Login<'_>>) -> private::IndexPostReturn {
    let (username, domain) = match login.email.split_once("@") {
        None => return private::IndexPostReturn::Html(rocket::response::content::RawHtml(const_format::concatcp!(HEAD, r#"<div class="error">The provided email didn't include an @ sign</div>"#, TAIL))),
        Some(v) => v,
    };
    #[cfg(debug_assertions)]
    log::debug!("username: {username}, domain: {domain}");

    let mysql = match crate::get_mysql().await{
        Ok(v) => v,
        Err(err) => {
            log::error!("Error getting mysql connection: {err}");
            return private::IndexPostReturn::Html(rocket::response::content::RawHtml(const_format::concatcp!(HEAD, r#"<div class="error">The server's database connection had an error. Please try again later.</div>"#, TAIL)))
        },
    };

    const ERROR:&str = const_format::concatcp!(HEAD, r#"<div class="error">Either no email exists, the password was incorrect or you are not permitted to login to the Web-Panel</div>"#, TAIL);
    let (user_id, self_change_pw) = match sqlx::query!(r#"
    SELECT
        users.id as id,
        COALESCE(user_perm.self_change_password, true) as "self_change_pw!",
        users.password as password
    FROM  virtual_users          users
    JOIN  virtual_domains        domains    ON users.domain_id = domains.id
    JOIN  web_domain_permissions perms       ON perms.user_id   = users.id
    LEFT JOIN user_permission   user_perm  ON user_perm.id = users.id
    WHERE perms.web_login = true AND users.email = $1 AND domains.name = $2"#, username, domain)
        .fetch_one(mysql)
        .await
    {
        Err(err) => {
            #[cfg(debug_assertions)]
            log::debug!("error getting email account: {err}");
            return private::IndexPostReturn::Html(rocket::response::content::RawHtml(ERROR))
        }
        Ok(out) => {
            match pw_hash::unix::verify(login.password, out.password.as_str()) {
                false => {
                    #[cfg(debug_assertions)]
                    log::debug!("Password incorrect!");
                    return private::IndexPostReturn::Html(rocket::response::content::RawHtml(ERROR))
                }
                true => {
                    (out.id, out.self_change_pw)
                },
            }
        }
    };

    let permissions = {
        let out = sqlx::query!(r#"
SELECT
        perm_domain.name as domain,
        perm.admin as "admin!",
        perm.web_login as "web_login!",
        perm.view_domain as "view_domain!",
        perm.create_subdomain as "create_subdomain!",
        perm.delete_subdomain as "delete_subdomain!",
        perm.list_accounts as "list_accounts!",
        perm.create_accounts as "create_accounts!",
        perm.modify_accounts as "modify_accounts!",
        perm.create_alias as "create_alias!",
        perm.modify_alias as "modify_alias!",
        perm.list_permissions as "list_permissions!",
        perm.manage_permissions as "manage_permissions!"
FROM flattened_web_domain_permissions perm
    JOIN virtual_domains perm_domain ON perm.domain_id=perm_domain.id
        WHERE perm.web_login = true AND perm.user_id = $1"#, user_id)
            .fetch_all(mysql)
            .await;
        let out = match out {
            Err(err) => {
                #[cfg(debug_assertions)]
                log::debug!("Error getting permissions: {err}");
                return private::IndexPostReturn::Html(rocket::response::content::RawHtml(const_format::concatcp!(HEAD, r#"<div class="error">Could not get user permissions. Please try again later.</div>"#, TAIL)))
            }
            Ok(out) => out,
        };

        out.into_iter().map(|v|
            (v.domain, super::session::Permission::new(
                v.admin,
                v.web_login,
                v.view_domain,
                v.create_subdomain,
                v.delete_subdomain,
                v.list_accounts,
                v.create_accounts,
                v.modify_accounts,
                v.create_alias,
                v.modify_alias,
                v.list_permissions,
                v.manage_permissions,
            ))
        ).collect::<std::collections::HashMap<_,_>>()
    };

    let session = super::session::Session::new(
        user_id,
        self_change_pw,
        permissions,
    );

    let cookie = match session.get_cookie() {
        Ok(v) => v,
        Err(err) => {
            #[cfg(debug_assertions)]
            log::error!("Error creating cookie: {err}");
            return private::IndexPostReturn::Html(rocket::response::content::RawHtml(const_format::concatcp!(HEAD, r#"<div class="error">An error occurred while creating the session cookie. Please try again later.</div>"#, TAIL)))
        }
    };
    cookies.add_private(cookie);

    private::IndexPostReturn::Redirect(rocket::response::Redirect::to(rocket::uri!("/admin")))
}


#[rocket::post("/logout")]
pub fn logout_post(cookies: &rocket::http::CookieJar<'_>) -> private::IndexPostReturn {
    match cookies.get_private("email") {
        Some(v) => cookies.remove_private(v),
        None => {},
    }

    private::IndexPostReturn::Redirect(rocket::response::Redirect::to(rocket::uri!("/")))
}
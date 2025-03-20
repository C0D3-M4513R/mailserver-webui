use crate::rocket::content::email_settings::SETTINGS;
use super::super::messages::{GET_PERMISSION_ERROR, INCORRECT_PASSWORD, OTHER_PASSWORD_ISSUE};
use crate::WEBMAIL_DOMAIN;

const HEAD:&str = const_format::formatcp!(r#"<!Doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="color-scheme" content="light dark">
        <title>Mailserver Admin</title>
    </head>
    <body>
        <h1>Mailserver Admin</h1>
                <a href="{WEBMAIL_DOMAIN}">Webmail</a>
"#);
const CONTENT:&str = r#"        <form method="POST">
            <label>E-Mail: <input type="email" name="email"/></label>
            <label>Password: <input type="password" name="password"/></label>
            <label>Submit: <input type="submit"/></label>
        </form>
"#;
const TAIL:&str = r#"
    </body>
</html>"#;


#[rocket::get("/")]
pub fn index_get(session: Option<super::Session>) -> private::IndexPostReturn {
    match session {
        None => private::IndexPostReturn::Html(rocket::response::content::RawHtml(const_format::concatcp!(HEAD, CONTENT, SETTINGS, TAIL))),
        Some(_) => private::IndexPostReturn::Redirect(rocket::response::Redirect::to(rocket::uri!("/admin")))
    }
}


mod private {
    #[derive(rocket::form::FromForm)]
    pub struct Login<'r> {
        pub(super) email: &'r str,
        pub(super) password: String,
    }
    #[derive(rocket::response::Responder)]
    pub enum IndexPostReturn {
        Html(rocket::response::content::RawHtml<&'static str>),
        Redirect(rocket::response::Redirect),
    }
}

#[rocket::post("/", data = "<login>")]
pub async fn index_post(ip: std::net::IpAddr, cookies: &rocket::http::CookieJar<'_>, login: rocket::form::Form<private::Login<'_>>) -> private::IndexPostReturn {
    let (username, domain) = match login.email.split_once("@") {
        None => return private::IndexPostReturn::Html(rocket::response::content::RawHtml(const_format::concatcp!(HEAD, r#"<div class="error">The provided email didn't include an @ sign</div>"#, TAIL))),
        Some(v) => v,
    };

    log::debug!("username: {username}, domain: {domain}");

    let pool = crate::get_db().await;

    let login = login.into_inner();
    const ERROR:&str = const_format::concatcp!(HEAD, INCORRECT_PASSWORD, CONTENT, SETTINGS, TAIL);
    let user_id = match sqlx::query!(r#"
    SELECT
        users.id as "id!"
    FROM  virtual_users          users
    JOIN  virtual_domains        domains    ON users.domain_id = domains.id
    WHERE users.email = $1 AND domains.name = $2"#, username, domain)
        .fetch_one(&pool)
        .await
    {
        Err(err) => {
            tracing::event!(target: crate::FAIL2BAN_TARGET, tracing::Level::TRACE, msg="Invalid email account", err=err.to_string(), host=?ip);
            log::debug!("error getting email account: {err}");
            return private::IndexPostReturn::Html(rocket::response::content::RawHtml(ERROR))
        }
        Ok(out) => {
            match super::check_password(pool.clone(), out.id, out.id, login.password, None).await {
                Err(super::AuthError::VerifyPassword(err)) => {
                    tracing::event!(target: crate::FAIL2BAN_TARGET, tracing::Level::TRACE, msg="Invalid password", err=err.to_string(), host=?ip);

                    log::debug!("Password incorrect: {err}");
                    return private::IndexPostReturn::Html(rocket::response::content::RawHtml(ERROR))
                }
                Err(err) => {

                    log::debug!("Error checking password: {err}");
                    return private::IndexPostReturn::Html(rocket::response::content::RawHtml(const_format::concatcp!(HEAD, OTHER_PASSWORD_ISSUE, CONTENT, SETTINGS, TAIL)))
                }
                Ok(()) => out.id,
            }
        }
    };

    let session = match super::Session::new(
        user_id,
        pool
    ).await {
        Ok(v) => v,
        Err(err) => {

            log::error!("Error creating session: {err}");
            return private::IndexPostReturn::Html(rocket::response::content::RawHtml(const_format::concatcp!(HEAD, GET_PERMISSION_ERROR, CONTENT, SETTINGS, TAIL)))
        }
    };

    let cookie = match session.get_cookie() {
        Ok(v) => v,
        Err(err) => {

            log::error!("Error creating cookie: {err}");
            return private::IndexPostReturn::Html(rocket::response::content::RawHtml(const_format::concatcp!(HEAD, r#"<div class="error">An error occurred while creating the session cookie. Please try again later.</div>"#, CONTENT, SETTINGS, TAIL)))
        }
    };
    cookies.add_private(cookie);

    private::IndexPostReturn::Redirect(rocket::response::Redirect::to(rocket::uri!("/admin")))
}
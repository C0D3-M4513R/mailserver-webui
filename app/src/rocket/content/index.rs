use super::super::messages::{DATABASE_TRANSACTION_ERROR, GET_PERMISSION_ERROR, INCORRECT_PASSWORD, OTHER_PASSWORD_ISSUE};

const HEAD:&str = r#"<!Doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="color-scheme" content="light dark">
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
pub fn index_get(session: Option<super::Session>) -> private::IndexPostReturn {
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

    log::debug!("username: {username}, domain: {domain}");

    let mysql = crate::get_mysql().await;

    const ERROR:&str = const_format::concatcp!(HEAD, INCORRECT_PASSWORD, TAIL);
    let (user_id, self_change_pw) = match sqlx::query!(r#"
    SELECT
        users.id as "id!",
        COALESCE(user_perm.self_change_password, true) as "self_change_pw!"
    FROM  virtual_users          users
    JOIN  virtual_domains        domains    ON users.domain_id = domains.id
    LEFT JOIN user_permission   user_perm  ON user_perm.id = users.id
    WHERE users.email = $1 AND domains.name = $2"#, username, domain)
        .fetch_one(mysql)
        .await
    {
        Err(err) => {

            log::debug!("error getting email account: {err}");
            return private::IndexPostReturn::Html(rocket::response::content::RawHtml(ERROR))
        }
        Ok(out) => {
            match super::check_password(out.id, out.id, login.password, None).await {
                Err(super::AuthError::VerifyPassword(err)) => {

                    log::debug!("Password incorrect: {err}");
                    return private::IndexPostReturn::Html(rocket::response::content::RawHtml(ERROR))
                }
                Err(super::AuthError::TransactionBegin(err)) | Err(super::AuthError::TransactionCommit(err)) => {
                    log::debug!("Error beginning or commiting transaction to database: {err}!");
                    return private::IndexPostReturn::Html(rocket::response::content::RawHtml(const_format::concatcp!(HEAD, DATABASE_TRANSACTION_ERROR, TAIL)))
                }
                Err(err) => {

                    log::debug!("Error checking password: {err}");
                    return private::IndexPostReturn::Html(rocket::response::content::RawHtml(const_format::concatcp!(HEAD, OTHER_PASSWORD_ISSUE, TAIL)))
                }
                Ok(()) => (out.id, out.self_change_pw),
            }
        }
    };

    let session = match super::Session::new(
        user_id,
        self_change_pw,
    ).await {
        Ok(v) => v,
        Err(err) => {

            log::error!("Error creating session: {err}");
            return private::IndexPostReturn::Html(rocket::response::content::RawHtml(const_format::concatcp!(HEAD, GET_PERMISSION_ERROR, TAIL)))
        }
    };

    let cookie = match session.get_cookie() {
        Ok(v) => v,
        Err(err) => {

            log::error!("Error creating cookie: {err}");
            return private::IndexPostReturn::Html(rocket::response::content::RawHtml(const_format::concatcp!(HEAD, r#"<div class="error">An error occurred while creating the session cookie. Please try again later.</div>"#, TAIL)))
        }
    };
    cookies.add_private(cookie);

    private::IndexPostReturn::Redirect(rocket::response::Redirect::to(rocket::uri!("/admin")))
}
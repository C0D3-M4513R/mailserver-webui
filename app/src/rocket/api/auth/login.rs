use std::borrow::Cow;
use rocket::http::Status;
use crate::rocket::auth::check_password::{check_password, Error as AuthError};
use crate::rocket::auth::session::Session;
use crate::rocket::messages::{GET_PERMISSION_ERROR, INCORRECT_PASSWORD, OTHER_PASSWORD_ISSUE};
use crate::rocket::response::Return;
use crate::rocket::template::login::Login;

#[rocket::post("/auth/login", data = "<login>")]
pub async fn index_post(ip: std::net::IpAddr, cookies: &rocket::http::CookieJar<'_>, login: rocket::form::Form<crate::rocket::content::index::private::Login<'_>>) -> Return {
    let (username, domain) = match login.email.split_once("@") {
        None => return (Status::BadRequest, Login{error: Some(Cow::Borrowed("The provided email didn't include an @ sign"))}).into(),
        Some(v) => v,
    };

    log::debug!("username: {username}, domain: {domain}");

    let pool = crate::get_db().await;

    let login = login.into_inner();

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
            return (Status::InternalServerError, Login{error: Some(Cow::Borrowed(INCORRECT_PASSWORD))}).into();
        }
        Ok(out) => {
            match check_password(pool.clone(), out.id, out.id, login.password, None).await {
                Err(AuthError::VerifyPassword(err)) => {
                    tracing::event!(target: crate::FAIL2BAN_TARGET, tracing::Level::TRACE, msg="Invalid password", err=err.to_string(), host=?ip);

                    log::debug!("Password incorrect: {err}");
                    return (Status::Forbidden, Login{error: Some(Cow::Borrowed(INCORRECT_PASSWORD))}).into();
                }
                Err(err) => {
                    log::debug!("Error checking password: {err}");
                    return (Status::InternalServerError, Login{error: Some(Cow::Borrowed(OTHER_PASSWORD_ISSUE))}).into()
                }
                Ok(()) => out.id,
            }
        }
    };

    let session = match Session::new(
        user_id,
        pool
    ).await {
        Ok(v) => v,
        Err(err) => {
            log::error!("Error creating session: {err}");
            return (Status::InternalServerError, Login{error: Some(Cow::Borrowed(GET_PERMISSION_ERROR))}).into()
        }
    };

    let cookie = match session.get_cookie() {
        Ok(v) => v,
        Err(err) => {
            log::error!("Error creating cookie: {err}");
            return (Status::InternalServerError, Login{error: Some(Cow::Borrowed("An error occurred while creating the session cookie. Please try again later."))}).into()
        }
    };
    cookies.add_private(cookie);

    Return::Redirect(rocket::response::Redirect::to(rocket::uri!("/admin")))
}
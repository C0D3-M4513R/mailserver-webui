use std::borrow::Cow;
use crate::rocket::auth::check_password::{check_password, Error as AuthError};
use crate::rocket::auth::session::Session;
use crate::rocket::messages::{GET_PERMISSION_ERROR, INCORRECT_PASSWORD, OTHER_PASSWORD_ISSUE};
use crate::rocket::response::Return;
use crate::rocket::template::login::Login;

#[actix_web::post("/auth/login")]
pub async fn index_post(req: actix_web::HttpRequest, key: actix_web::web::Data<actix_web::cookie::Key>, mut login: actix_web::web::Form<crate::rocket::content::index::private::Login>) -> Return {
    let (username, domain) = match login.email.split_once("@") {
        None => return (actix_web::http::StatusCode::BAD_REQUEST, Login{error: Some(Cow::Borrowed("The provided email didn't include an @ sign"))}).into(),
        Some(v) => v,
    };

    let conn = req.connection_info();
    let ip = conn.realip_remote_addr();

    log::debug!("username: {username}, domain: {domain}");

    let pool = crate::get_db().await;

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
            return (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, Login{error: Some(Cow::Borrowed(INCORRECT_PASSWORD))}).into();
        }
        Ok(out) => {
            match check_password(pool.clone(), out.id, out.id, core::mem::take(&mut login.password), None).await {
                Err(AuthError::VerifyPassword(err)) => {
                    tracing::event!(target: crate::FAIL2BAN_TARGET, tracing::Level::TRACE, msg="Invalid password", err=err.to_string(), host=?ip);

                    log::debug!("Password incorrect: {err}");
                    return (actix_web::http::StatusCode::FORBIDDEN, Login{error: Some(Cow::Borrowed(INCORRECT_PASSWORD))}).into();
                }
                Err(err) => {
                    log::debug!("Error checking password: {err}");
                    return (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, Login{error: Some(Cow::Borrowed(OTHER_PASSWORD_ISSUE))}).into()
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
            return (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, Login{error: Some(Cow::Borrowed(GET_PERMISSION_ERROR))}).into()
        }
    };

    let cookie = match session.get_cookie() {
        Ok(v) => v,
        Err(err) => {
            log::error!("Error creating cookie: {err}");
            return (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, Login{error: Some(Cow::Borrowed("An error occurred while creating the session cookie. Please try again later."))}).into()
        }
    };
    let mut ret = Return::redirect_to_value(actix_web::http::header::HeaderValue::from_static("/admin"));

    let mut cookies = actix_web::cookie::CookieJar::new();
    let mut private = cookies.private_mut(&*key);
    private.add(cookie);
    drop(private);
    for i in cookies.delta() {
        ret.add_cookie(i);
    }
    drop(cookies);

    ret
}
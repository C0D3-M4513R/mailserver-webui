use rocket::http::CookieJar;
use crate::rocket::response::Return;

#[rocket::post("/admin/refresh_session")]
pub async fn post_refresh_session(mut session: super::super::Session, cookies: &CookieJar<'_>) -> Return {
    let pool = crate::get_mysql().await;
    match session.refresh_permissions(pool, cookies).await {
        Ok(()) => {},
        Err(err) => {

            log::error!("Error whilst refreshing session: {err}");
            return Return::Redirect(rocket::response::Redirect::to(rocket::uri!("/")));
        }
    };

    Return::Redirect(rocket::response::Redirect::to(rocket::uri!("/admin")))
}
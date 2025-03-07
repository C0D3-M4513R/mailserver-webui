use rocket::http::CookieJar;

#[rocket::post("/admin/refresh_session")]
pub async fn post_refresh_session(mut session: super::super::Session, cookies: &CookieJar<'_>) -> Result<rocket::http::Status,rocket::response::Redirect> {
    match session.refresh_permissions(cookies).await {
        Ok(()) => {},
        Err(err) => {
            #[cfg(debug_assertions)]
            log::error!("Error whilst refreshing session: {err}");
            return Err(rocket::response::Redirect::to(rocket::uri!("/")));
        }
    };

    Ok(rocket::http::Status::NoContent)
}
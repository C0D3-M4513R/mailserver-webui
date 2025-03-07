use rocket::http::CookieJar;

#[rocket::post("/admin/refresh_session")]
pub async fn post_refresh_session(session: super::super::Session, cookies: &CookieJar<'_>) -> Result<rocket::http::Status,rocket::response::Redirect> {
    let session = match super::super::Session::new(
        session.get_user_id(),
        session.get_self_change_password(),
    ).await {
        Ok(v) => v,
        Err(err) => {
            super::super::Session::remove_cookie(cookies);
            #[cfg(debug_assertions)]
            log::error!("Error creating session: {err}");
            return Err(rocket::response::Redirect::to(rocket::uri!("/")));
        }
    };
    match session.get_cookie() {
        Ok(v) => cookies.add_private(v),
        Err(err) => {
            super::super::Session::remove_cookie(cookies);
            #[cfg(debug_assertions)]
            log::error!("Error creating cookie: {err}");
            return Err(rocket::response::Redirect::to(rocket::uri!("/")));
        }
    }


    Ok(rocket::http::Status::NoContent)
}
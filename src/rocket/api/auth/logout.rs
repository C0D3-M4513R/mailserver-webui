#[rocket::post("/logout")]
pub fn logout_post(cookies: &rocket::http::CookieJar<'_>) -> rocket::response::Redirect {
    match cookies.get_private("email") {
        Some(v) => cookies.remove_private(v),
        None => {},
    }

    rocket::response::Redirect::to(rocket::uri!("/"))
}
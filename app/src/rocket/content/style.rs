#[actix_web::get("/styles.css")]
pub async fn get_styles_css() -> crate::rocket::response::Return {
    crate::rocket::response::Return::new(Some(std::borrow::Cow::Borrowed(include_str!("../../../templates/styles.css"))))
        .override_status(actix_web::http::StatusCode::OK)
        .override_content_type(actix_web::http::header::ContentType(actix_web::mime::TEXT_CSS))
}
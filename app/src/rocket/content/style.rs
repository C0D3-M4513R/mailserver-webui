#[rocket::get("/styles.css")]
pub const fn get_styles_css() -> rocket::response::content::RawCss<&'static str> {
    rocket::response::content::RawCss(include_str!("../../../templates/styles.css"))
}
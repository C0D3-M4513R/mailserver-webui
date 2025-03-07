pub const JSON_ERROR_MEDIA_TYPE: rocket::http::MediaType = rocket::http::MediaType::const_new(
    "application",
    "vnd.com.c0d3m4513r.mail-error.v1+json",
    &[]
);
pub const JSON_ERROR_CONTENT_TYPE: rocket::http::ContentType = rocket::http::ContentType(JSON_ERROR_MEDIA_TYPE);
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "v")]
pub enum Error{
    V1(ErrorV1),
}
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ErrorV1 {
    pub error: String,
}
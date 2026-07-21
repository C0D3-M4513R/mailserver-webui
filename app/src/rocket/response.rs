use std::borrow::Cow;
use crate::rocket::template::error::TemplateError;

pub struct Return {
    status: actix_web::http::StatusCode,
    lock_status: bool,
    headers: actix_web::http::header::HeaderMap,
    lock_content_type: bool,
    body: Option<Cow<'static, str>>,
}
impl Default for Return {
    fn default() -> Self {
        Self {
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            lock_status: false,
            headers: actix_web::http::header::HeaderMap::new(),
            lock_content_type: false,
            body: None,
        }
    }
}
impl Return {
    pub fn new(body: Option<Cow<'static, str>>) -> Self {
        Self {
            body,
            ..Self::default()
        }
    }
    pub const fn override_status(mut self, status: actix_web::http::StatusCode) -> Self{
        if self.lock_status { return self; }

        self.status = status;
        self
    }
    pub const fn lock_status(mut self) -> Self {
        self.lock_status = true;
        self
    }
    pub fn override_content_type(mut self, content_type: actix_web::http::header::ContentType) -> Self{
        if self.lock_content_type { return self; }

        match <actix_web::http::header::ContentType as actix_web::http::header::TryIntoHeaderValue>::try_into_value(content_type){
            Ok(v) => {
                self.headers.insert(actix_web::http::header::CONTENT_TYPE, v);
            },
            Err(e) => {
                tracing::error!("Failed to convert content type header to header value: {e}");
            }
        }

        self
    }
    pub fn add_cookie(&mut self, cookie: &actix_web::cookie::Cookie<'_>) {
        match actix_web::http::header::HeaderValue::from_str(&cookie.to_string())
        {
            Ok(cookie) => self.headers.append(actix_web::http::header::SET_COOKIE, cookie),
            Err(e) => {
                tracing::error!("Failed to set cookie header: error: {e}, cookie: {cookie}");
            }
        }
    }
    pub fn redirect_to(target: String) -> Self {
        let mut slf = Self{
            status: actix_web::http::StatusCode::SEE_OTHER,
            lock_status: true,

            ..  Self::default()
        };
        match actix_web::http::header::HeaderValue::try_from(target.as_str()) {
            Ok(v) => {
                slf.headers.insert(actix_web::http::header::LOCATION, v);
            },
            Err(e) => {
                tracing::error!("Couldn't convert specified target ({target}) into a HeaderValue: {e}");
                slf.status = actix_web::http::StatusCode::FOUND;
                slf.body = Some(Cow::Owned(format!(r#"<!Doctype html><html><head><meta http-equiv="refresh" content="0; url={target}"></head><body><p>Using http based redirect, because the server failed to redirect to {target} via a Http-Location Header.</p></body></html>"#)));
                slf = slf.override_content_type(actix_web::http::header::ContentType::html());
            }
        }

        slf
    }
    pub fn redirect_to_value(target: actix_web::http::header::HeaderValue) -> Self {
        let mut slf = Self{
            status: actix_web::http::StatusCode::SEE_OTHER,
            lock_status: true,

            ..  Self::default()
        };
        slf.headers.insert(actix_web::http::header::LOCATION, target);
        slf
    }
}

impl<T: askama::Template> From<(actix_web::http::StatusCode, T)> for Return {
    fn from(value: (actix_web::http::StatusCode, T)) -> Self {
        match value.1.render().map_err(TemplateError::from) {
            Ok(v) => {
                Self::new(Some(Cow::Owned(v)))
                    .override_status(value.0)
                    .override_content_type(actix_web::http::header::ContentType::html())
            },
            Err(e) => {
                Self::new(Some(Cow::Owned(e.to_string())))
                    .override_status(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR)
                    .lock_status()
                    .override_content_type(actix_web::http::header::ContentType::plaintext())
            },
        }
    }
}
impl From<actix_web::http::StatusCode> for Return {
    fn from(status: actix_web::http::StatusCode) -> Self {
        Self {
            status,
            ..Self::default()
        }
    }
}
impl actix_web::Responder for Return {
    type Body = actix_web::body::EitherBody<Cow<'static, str>, actix_web::body::None>;
    fn respond_to(self, _: &actix_web::HttpRequest) -> actix_web::HttpResponse<Self::Body> {
        let body = self.body.map_or(actix_web::body::EitherBody::Right {body: actix_web::body::None::new()}, actix_web::body::EitherBody::left);
        let mut resp = actix_web::HttpResponse::with_body(self.status, body);
        *resp.headers_mut() = self.headers;
        resp
    }
}
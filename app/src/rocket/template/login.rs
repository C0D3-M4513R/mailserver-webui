use std::borrow::Cow;
use askama::Template;

#[derive(Template, Default)]
#[template(path = "login.html")]
pub struct Login{
    pub error: Option<Cow<'static, str>>,
}
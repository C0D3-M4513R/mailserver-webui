use std::borrow::Cow;
use askama::Template;
#[derive(Template)]
#[template(path = "change_pw.html")]
pub struct ChangePw{
    pub error: Option<Cow<'static, str>>,
    pub block_change_pw: bool,
}
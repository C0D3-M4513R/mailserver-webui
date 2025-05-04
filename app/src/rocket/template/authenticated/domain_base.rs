use std::fmt::Display;
use askama::{FastWritable, Template};

#[derive(Template)]
#[template(path = "authenticated/domain_base.html")]
pub struct DomainBase<'a, T: FastWritable + Display> {
    pub domain: &'a str,
    pub content: T,
}
use std::fmt::Display;
use askama::{FastWritable, Template};
use crate::rocket::auth::session::Permission;

#[derive(Template)]
#[template(path = "authenticated/domain_base.html")]
pub struct DomainBase<'a, T: FastWritable + Display> {
    pub domain: &'a str,
    pub permission: Option<Permission>,
    pub content: T,
}
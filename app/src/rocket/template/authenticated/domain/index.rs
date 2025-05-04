use askama::Template;
use crate::rocket::auth::session::Permission;

#[derive(Template)]
#[template(path = "authenticated/domain/index.html")]
pub struct DomainIndex<'a> {
    pub domain: &'a str,
    pub permissions: &'a Permission,
    pub rename: Option<DomainName>,
    pub accounts: Vec<DomainAccount>,
}

pub struct DomainAccount{
    pub id: i64,
    pub true_owner: bool,
    pub email: String,
    pub domain: String,
}
pub struct DomainName{
    pub self_name: String,
    pub super_name: String,
}
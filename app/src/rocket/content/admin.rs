pub mod domain;

pub use domain::{admin_domain_get, admin_domain_accounts_get, admin_domain_account_get, admin_domain_subdomains_get, admin_domain_permissions_get, admin_domain_aliases_get};

use super::{Return, Session};
use crate::rocket::auth::session::Permission;
use crate::rocket::template::authenticated::admin::Admin;

pub(super) fn sort_permissions<'a>(permissions: impl Iterator<Item = (&'a String, &'a Permission)>) -> Vec<(&'a String, &'a Permission)> {
    let mut permissions = permissions.collect::<Vec<_>>();
    permissions.sort_by(|(k1, p1), (k2, p2)| {
        (p1.domain_level(), k1).cmp(&(p2.domain_level(), k2))
    });
    permissions
}
#[rocket::get("/admin")]
pub async fn admin_get(session: Option<Session>) -> Return {
    let session = match session {
        None => return Return::Redirect(rocket::response::Redirect::to(rocket::uri!("/"))),
        Some(v) => v,
    };

    let permissions = sort_permissions(
        session.get_permissions()
            .iter()
            .filter(|(_, permissions)|permissions.admin() || permissions.view_domain())
    );

    (rocket::http::Status::Ok, Admin{
            domains: permissions.into_iter().map(|(k, _)| k).collect::<Vec<_>>().as_slice()
    }).into()
}
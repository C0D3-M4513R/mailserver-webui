use super::response::Return;
use super::auth::session::Session;
pub mod index;
pub mod admin;
pub mod change_pw;

pub use index::{index_get};
pub use admin::{
    admin_domain_accounts_get, admin_domain_account_get,
    admin_domain_subdomains_get,
    admin_domain_permissions_get,
    admin_domain_aliases_get,
    admin_domain_get,
    admin_get
};
pub use change_pw::{admin_get_change_pw};
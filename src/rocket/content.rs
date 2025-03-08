use super::response::{Return, TypedContent};
use super::session::{Session, HEADER as SESSION_HEADER};
use super::auth::check_password::{check_password, Error as AuthError};
pub mod index;
pub mod admin;
pub mod change_pw;

pub use index::{index_post, index_get};
pub use admin::{
    admin_domain_accounts_get, admin_domain_account_get,
    admin_domain_subdomains_get,
    admin_domain_get,
    admin_get
};
pub use change_pw::{admin_get_change_pw};
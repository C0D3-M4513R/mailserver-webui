pub mod delete_accounts;
mod create_account;
mod update_account;
mod create_subdomain;
mod delete_subdomains;

pub use delete_accounts::{admin_domain_accounts_delete, admin_domain_account_delete};
pub use create_account::{create_account as admin_domain_accounts_put};
pub use update_account::{admin_domain_account_email_put, admin_domain_account_password_put, admin_domain_account_permissions_put};
pub use create_subdomain::{admin_domain_subdomains_put};
pub use delete_subdomains::{admin_domain_subdomains_delete};

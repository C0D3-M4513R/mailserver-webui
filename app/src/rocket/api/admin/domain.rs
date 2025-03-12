pub mod delete_accounts;
mod create_account;
mod update_account;
mod create_subdomain;
mod delete_subdomains;
mod update_domain;
mod change_owner;
mod create_alias;
mod delete_alias;

pub use delete_accounts::{admin_domain_accounts_delete, admin_domain_account_delete, admin_domain_accounts_delete_post, admin_domain_accounts_restore_post};
pub use create_account::{create_account as admin_domain_accounts_put};
pub use update_account::{admin_domain_account_email_put, admin_domain_account_password_put, admin_domain_account_user_permission_put, admin_domain_account_permissions_put};

pub use delete_alias::{admin_domain_aliases_delete, admin_domain_account_aliases_delete};
pub use create_alias::{admin_domain_aliases_put};


pub use create_subdomain::{admin_domain_subdomains_put};
pub use delete_subdomains::{admin_domain_subdomains_delete, admin_domain_subdomains_delete_post, admin_domain_subdomains_recover_post,};

pub use change_owner::{admin_domain_owner_put};
pub use update_domain::{admin_domain_name_put, admin_domain__accepts_email__put, admin_domain_permissions_put};

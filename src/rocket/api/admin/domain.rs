pub mod delete_accounts;
mod create_account;

pub use delete_accounts::admin_domain_accounts_delete;
pub use create_account::{create_account as admin_domain_accounts_put};
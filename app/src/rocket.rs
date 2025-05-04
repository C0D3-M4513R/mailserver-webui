mod messages;
mod auth;
mod response;
mod api;
mod content;
mod template;

pub use api::{
    index_post,
    auth_check_login,
    admin_domain_accounts_delete,
    admin_domain_accounts_delete_post,
    admin_domain_accounts_restore_post,
    admin_domain_account_delete,
    admin_domain_account_email_put,
    admin_domain_account_password_put,
    admin_domain_account_user_permission_put,
    admin_domain_account_permissions_put,
    admin_domain_account_aliases_delete,
    admin_domain_accounts_put,
    admin_domain_subdomains_put,
    admin_domain_subdomains_delete,
    admin_domain_subdomains_delete_post,
    admin_domain_subdomains_recover_post,
    admin_domain_aliases_delete,
    admin_domain_aliases_put,
    logout_post,
    admin_put_change_pw,
    admin_domain_name_put,
    admin_domain__accepts_email__put,
    admin_domain_permissions_put,
    admin_domain_owner_put,
};
pub use content::{
    index_get,
    admin_get_change_pw,
    admin_domain_accounts_get, admin_domain_account_get,
    admin_domain_subdomains_get,
    admin_domain_permissions_get,
    admin_domain_aliases_get,
    admin_domain_get,
    admin_get,
};
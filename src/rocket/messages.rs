pub const INCORRECT_PASSWORD:&str = r#"Either no email exists or the provided password was incorrect"#;
pub const OTHER_PASSWORD_ISSUE:&str = r#"There was an unknown Error, whilst verifying your Login information."#;
pub const GET_PERMISSION_ERROR:&str = r#"There was an Error, whilst fetching your permissions."#;
pub const SELF_CHANGE_PASSWORD_NO_PERM:&str = r#"You don't have the permission to change your password."#;
pub const SELF_CHANGE_PASSWORD_ERROR:&str = r#"There was an error whilst trying to change your password."#;
pub const CREATE_ACCOUNT_NO_PERM:&str = r#"You don't have the permission to create this accounts."#;
pub const DELETE_ACCOUNT_NO_PERM:&str = r#"You don't have the permission to delete this account."#;
pub const MODIFY_ACCOUNT_NO_PERM:&str = r#"You don't have the permission to modify accounts."#;
pub const CREATE_SUBDOMAIN_NO_PERM:&str = r#"You don't have the permission to create subdomains."#;
pub const DELETE_SUBDOMAIN_NO_PERM:&str = r#"You don't have the permission to delete subdomains."#;
pub const MODIFY_DOMAIN_NO_PERM:&str = r#"You don't have the permission to modify this domain."#;

pub const MANAGE_PERMISSION_NO_PERM:&str = r#"You don't have the permission to manage permissions."#;
pub const INVALID_CONTENT_TYPE:&str = r#"The request had an unexpected content type."#;
pub const DATABASE_ERROR:&str = r#"There was an error whilst commiunicating with the internal Database. Please try again later."#;
pub const DATABASE_TRANSACTION_ERROR:&str = DATABASE_ERROR;
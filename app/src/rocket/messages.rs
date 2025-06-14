pub const SESSION_ISSUE:&str = r#"You are not logged-in."#;

pub const INCORRECT_PASSWORD:&str = r#"Either no email exists or the provided password was incorrect"#;
pub const OTHER_PASSWORD_ISSUE:&str = r#"There was an unknown Error, whilst verifying your Login information."#;
pub const GET_PERMISSION_ERROR:&str = r#"There was an Error, whilst fetching your permissions."#;
pub const SELF_CHANGE_PASSWORD_NO_PERM:&str = r#"You don't have the permission to change your password."#;
pub const SELF_CHANGE_PASSWORD_ERROR:&str = r#"There was an error whilst trying to change your password."#;

pub const VIEW_ADMIN_PANEL_NO_PERM:&str = r#"You don't have the permission to enter the admin panel."#;
pub const VIEW_ADMIN_PANEL_DOMAIN_NO_PERM:&str = r#"You are unable to access the Admin-Panel for this domain."#;
pub const LIST_ACCOUNT_NO_PERM:&str = r#"You don't have the permission to list accounts."#;
pub const CREATE_ACCOUNT_NO_PERM:&str = r#"You don't have the permission to create this accounts."#;
pub const DELETE_ACCOUNT_NO_PERM:&str = r#"You don't have the permission to delete this account."#;
pub const MODIFY_ACCOUNT_NO_PERM:&str = r#"You don't have the permission to modify accounts."#;
pub const ACCOUNT_INVALID_CHARS:&str = r#"The account name you entered was invalid."#;

pub const CREATE_ALIAS_NO_PERM:&str = r#"You don't have the permission to create aliases."#;
pub const DELETE_ALIAS_NO_PERM:&str = r#"You don't have the permission to delete aliases."#;
pub const ALIAS_INVALID_CHARS:&str = r#"The alias name you entered was invalid."#;

pub const DELETE_DISABLED_NO_PERM:&str = r#"You don't have the permission to delete disabled items."#;
pub const UNDELETE_DISABLED_NO_PERM:&str = r#"You don't have the permission to recover disabled items."#;


pub const VIEW_DOMAIN_NO_PERM:&str = r#"You don't have the permission to view this domain."#;

pub const CREATE_SUBDOMAIN_NO_PERM:&str = r#"You don't have the permission to create subdomains."#;
pub const SUBDOMAIN_INVALID_CHARS:&str = r#"The (sub)domain name you entered was invalid."#;
pub const DELETE_SUBDOMAIN_NO_PERM:&str = r#"You don't have the permission to delete subdomains."#;
pub const MODIFY_DOMAIN_NO_PERM:&str = r#"You don't have the permission to modify this domain."#;
pub const OWNER_DOMAIN_NO_PERM:&str = r#"You are not the owner of this domain."#;

pub const MANAGE_PERMISSION_NO_PERM:&str = r#"You don't have the permission to manage permissions."#;
pub const DATABASE_ERROR:&str = r#"There was an error whilst commiunicating with the internal Database. Please try again later."#;
pub const DATABASE_PERMISSION_ERROR:&str = r#"You don't thave the permission to perform this action."#;
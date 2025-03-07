pub const INCORRECT_PASSWORD:&str = r#"<div class="error">Either no email exists or the provided password was incorrect</div>"#;
pub const OTHER_PASSWORD_ISSUE:&str = r#"<div class="error">There was an unknown Error, whilst verifying your Login information.</div>"#;
pub const GET_PERMISSION_ERROR:&str = r#"<div class="error">There was an Error, whilst fetching your permissions.</div>"#;
pub const SELF_CHANGE_PASSWORD_NO_PERM:&str = r#"<p>You don't have the permission to change your password.</p>"#;
pub const SELF_CHANGE_PASSWORD_ERROR:&str = r#"<p>There was an error whilst trying to change your password.</p>"#;
pub const DELETE_ACCOUNT_NO_PERM:&str = r#"You don't have the permission to delete this account."#;
pub const INVALID_CONTENT_TYPE:&str = r#"The request had an unexpected content type."#;
pub const DATABASE_ERROR:&str = r#"<div class="error">There was an error whilst commiunicating with the internal Database. Please try again later.</div>"#;
pub const DATABASE_TRANSACTION_ERROR:&str = DATABASE_ERROR;
use std::collections::HashMap;
use crate::rocket::auth::session::Session;

#[derive(Debug, Default, Copy, Clone, serde::Serialize, serde::Deserialize, rocket::form::FromForm)]
pub struct Enabled<T> {
    pub enabled: bool,
    pub value: T,
}

mailserver_web_macro::query!();
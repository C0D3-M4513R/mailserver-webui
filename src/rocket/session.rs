use std::io::Read;
use base64::Engine;
use rocket::Request;
use rocket::request::Outcome;

#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
pub struct Permission {
    admin: bool,
    web_login: bool,
    view_domain: bool,
    create_subdomain: bool,
    delete_subdomain: bool,
    list_accounts: bool,
    create_accounts: bool,
    modify_accounts: bool,
    create_alias: bool,
    modify_alias: bool,
    list_permissions: i32,
    manage_permissions: i32,
}

impl Permission {
    pub fn new(
        admin: bool,
        web_login: bool,
        view_domain: bool,
        create_subdomain: bool,
        delete_subdomain: bool,
        list_accounts: bool,
        create_accounts: bool,
        modify_accounts: bool,
        create_alias: bool,
        modify_alias: bool,
        list_permissions: i32,
        manage_permissions: i32,
    ) -> Self {
        Self {
            admin,
            web_login,
            view_domain,
            create_subdomain,
            delete_subdomain,
            list_accounts,
            create_accounts,
            modify_accounts,
            create_alias,
            modify_alias,
            list_permissions,
            manage_permissions,
        }
    }
    #[inline] pub const fn get_admin(&self) -> bool { self.admin }
    #[inline] pub const fn get_view_domain(&self) -> bool { self.view_domain }
    #[inline] pub const fn get_create_subdomain(&self) -> bool { self.create_subdomain }
    #[inline] pub const fn get_delete_subdomain(&self) -> bool { self.delete_subdomain }
    #[inline] pub const fn get_list_accounts(&self) -> bool { self.list_accounts }
    #[inline] pub const fn get_create_accounts(&self) -> bool { self.create_accounts }
    #[inline] pub const fn get_modify_accounts(&self) -> bool { self.modify_accounts }
    #[inline] pub const fn get_create_alias(&self) -> bool { self.create_alias }
    #[inline] pub const fn get_modify_alias(&self) -> bool { self.modify_alias }
    #[inline] pub const fn get_web_login(&self) -> bool { self.web_login }
    #[inline] pub const fn get_list_permissions(&self) -> i32 { self.list_permissions }
    #[inline] pub const fn get_manage_permissions(&self) -> i32 { self.manage_permissions }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    user_id: i32,
    self_change_password: bool,
    permissions: std::collections::HashMap<String, Permission>,
}

impl Session{
    #[inline]
    pub const fn new(user_id: i32, self_change_password: bool, permissions: std::collections::HashMap<String, Permission>) -> Self {
        Self {
            user_id,
            self_change_password,
            permissions,
        }
    }

    pub fn get_cookie(&self) -> anyhow::Result<rocket::http::Cookie<'static>> {
        let json = match serde_json::to_vec(&self) {
            Ok(v) => v,
            Err(err) => {
                #[cfg(debug_assertions)]
                log::error!("Error serializing cookie: {err}");
                anyhow::bail!("Error serializing cookie: {err}");
            }
        };
        let mut out = Vec::new();

        match flate2::read::GzEncoder::new(json.as_slice(), flate2::Compression::fast())
            .read_to_end(&mut out)
        {
            Ok(_) => {},
            Err(err) => {
                #[cfg(debug_assertions)]
                log::error!("Error compressing cookie: {err}");
                anyhow::bail!("Error compressing cookie: {err}");
            },
        }
        let out = base64::engine::general_purpose::URL_SAFE.encode(out.as_slice());
        let mut cookie = rocket::http::Cookie::new("email", out);
        cookie.set_secure(true);
        cookie.set_http_only(true);
        Ok(cookie)
    }

    #[inline] pub const fn get_user_id(&self) -> i32 { self.user_id }
    #[inline] pub const fn get_self_change_password(&self) -> bool { self.self_change_password }
    #[inline] pub const fn get_permissions(&self) -> &std::collections::HashMap<String, Permission> { &self.permissions }
}

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for Session{
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let cookie = match request.cookies().get_private("email") {
            Some(cookie) => cookie,
            None => return Outcome::Forward(rocket::http::Status::Ok),
        };

        let email:Session = {
            use base64::Engine;
            let bytes = match base64::engine::general_purpose::URL_SAFE.decode(cookie.value().as_bytes()) {
                Ok(v) => v,
                Err(err) => {
                    #[cfg(debug_assertions)]
                    log::error!("Error decoding cookie from base64: {err}");
                    request.cookies().remove_private(cookie);
                    return Outcome::Forward(rocket::http::Status::Ok);
                },
            };
            let mut out = Vec::new();
            match flate2::bufread::GzDecoder::new(bytes.as_slice()).read_to_end(&mut out) {
                 Ok(_) => {},
                 Err(err) => {
                    #[cfg(debug_assertions)]
                    log::error!("Error decompressing cookie: {err}");
                    request.cookies().remove_private(cookie);
                    return Outcome::Forward(rocket::http::Status::Ok);
                },
            }

            match serde_json::from_slice(out.as_slice()) {
                Ok(v) => v,
                Err(err) => {
                    #[cfg(debug_assertions)]
                    log::error!("Error deserializing cookie: {err}, {out:?}");
                    request.cookies().remove_private(cookie);
                    return Outcome::Forward(rocket::http::Status::Ok);
                },
            }
        };

        Outcome::Success(email)
    }
}
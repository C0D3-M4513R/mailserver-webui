use std::io::Read;
use base64::Engine;
use rocket::Request;
use rocket::request::Outcome;
use crate::{get_db, WEBMAIL_DOMAIN};

pub use crate::rocket::auth::permissions::{Permission, UserPermission};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SessionCookie {
    pub(super) user_id: i64,
}
impl From<&Session> for SessionCookie {
    fn from(value: &Session) -> Self {
        Self {
            user_id: value.user_id,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub(super) user_id: i64,
    pub(super) user_permission: UserPermission,
    pub(super) permissions: std::collections::HashMap<String, Permission>,
}
impl Session{
    pub async fn refresh_permissions(&mut self, pool:sqlx::postgres::PgPool, cookies: &rocket::http::CookieJar<'_>) -> anyhow::Result<()> {
        let session = Self::new(self.user_id, pool).await?;
        match session.get_cookie() {
            Ok(v) => cookies.add_private(v),
            Err(err) => {
                Self::remove_cookie(cookies);

                log::error!("Error creating cookie: {err}");
                anyhow::bail!("Error creating cookie: {err}");
            }
        }
        self.permissions = session.permissions;
        Ok(())
    }
    pub fn remove_cookie(cookies: &rocket::http::CookieJar<'_>) {
        match cookies.get_private("email")  {
            Some(cookie) => cookies.remove_private(cookie),
            None => {},
        }
    }

    pub fn get_cookie(&self) -> anyhow::Result<rocket::http::Cookie<'static>> {
        let cookie = SessionCookie::from(self);
        let json = match serde_json::to_vec(&cookie) {
            Ok(v) => v,
            Err(err) => {

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

    #[inline] pub const fn get_user_id(&self) -> i64 { self.user_id }
    #[inline] pub const fn get_user_permission(&self) -> &UserPermission { &self.user_permission }
    #[inline] pub const fn get_permissions(&self) -> &std::collections::HashMap<String, Permission> { &self.permissions }
}

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for Session{
    type Error = sqlx::Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let cookie = match request.cookies().get_private("email") {
            Some(cookie) => cookie,
            None => return Outcome::Forward(rocket::http::Status::Ok),
        };

        let email:SessionCookie = {
            use base64::Engine;
            let bytes = match base64::engine::general_purpose::URL_SAFE.decode(cookie.value().as_bytes()) {
                Ok(v) => v,
                Err(err) => {

                    log::error!("Error decoding cookie from base64: {err}");
                    request.cookies().remove_private(cookie);
                    return Outcome::Forward(rocket::http::Status::Ok);
                },
            };
            let mut out = Vec::new();
            match flate2::bufread::GzDecoder::new(bytes.as_slice()).read_to_end(&mut out) {
                 Ok(_) => {},
                 Err(err) => {

                    log::error!("Error decompressing cookie: {err}");
                    request.cookies().remove_private(cookie);
                    return Outcome::Forward(rocket::http::Status::Ok);
                },
            }

            match serde_json::from_slice(out.as_slice()) {
                Ok(v) => v,
                Err(err) => {

                    log::error!("Error deserializing cookie: {err}, {out:?}");
                    request.cookies().remove_private(cookie);
                    return Outcome::Forward(rocket::http::Status::Ok);
                },
            }
        };
        let db = get_db().await;
        match Self::new(email.user_id, db).await {
            Ok(v) => Outcome::Success(v),
            Err(err) => {
                log::error!("Error creating session: {err}");
                Outcome::Error((rocket::http::Status::InternalServerError, err))
            }
        }
    }
}
pub const HEADER:&str = const_format::formatcp!(
    r#"
        {LOGOUT}
        <a href="/admin/change_pw">Change Password</a>
        <a href="{WEBMAIL_DOMAIN}">Webmail</a>
    "#,
);

const LOGOUT:&str = r#"
    <form action="/logout" method="POST">
        <input type="submit" value="Logout"></input>
    </form>
"#;
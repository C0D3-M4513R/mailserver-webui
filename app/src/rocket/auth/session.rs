use std::fmt::Formatter;
use std::io::Read;
use actix_web::HttpMessage;
use base64::Engine;
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
    pub async fn refresh_permissions(&mut self, pool:sqlx::postgres::PgPool, cookies: &mut actix_web::cookie::PrivateJar<&mut actix_web::cookie::CookieJar>) -> anyhow::Result<()> {
        let session = Self::new(self.user_id, pool).await?;
        match session.get_cookie() {
            Ok(v) => cookies.add(v),
            Err(err) => {
                Self::remove_cookie(cookies);

                log::error!("Error creating cookie: {err}");
                anyhow::bail!("Error creating cookie: {err}");
            }
        }
        self.permissions = session.permissions;
        Ok(())
    }
    pub fn remove_cookie(cookies: &mut actix_web::cookie::PrivateJar<&mut actix_web::cookie::CookieJar>) {
        match cookies.get("email")  {
            Some(cookie) => cookies.remove(cookie.clone()),
            None => {},
        }
    }

    pub fn get_cookie(&self) -> anyhow::Result<actix_web::cookie::Cookie<'static>> {
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
        let mut cookie = actix_web::cookie::Cookie::new("email", out);
        cookie.set_secure(true);
        cookie.set_http_only(true);
        Ok(cookie)
    }

    #[inline] pub const fn get_user_id(&self) -> i64 { self.user_id }
    #[inline] pub const fn get_user_permission(&self) -> &UserPermission { &self.user_permission }
    #[inline] pub const fn get_permissions(&self) -> &std::collections::HashMap<String, Permission> { &self.permissions }
}

pub async fn session_middleware(
    req: actix_web::dev::ServiceRequest,
    next: actix_web::middleware::Next<impl actix_web::body::MessageBody + 'static>,
) -> Result<actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>, actix_web::Error> {
    let cookie = match req.cookie("email") {
        Some(cookie) => cookie,
        None => {
            req.extensions_mut().insert(None::<Session>);
            return next.call(req).await;
        },
    };

    let err_resp = async |next: actix_web::middleware::Next<_>, req: actix_web::dev::ServiceRequest| {
        req.extensions_mut().insert(None::<Session>);
        let mut resp = next.call(req).await?;
        resp.response_mut().add_removal_cookie(&cookie)?;
        Ok(resp)
    };
    let email:SessionCookie = {
        use base64::Engine;
        let bytes = match base64::engine::general_purpose::URL_SAFE.decode(cookie.value().as_bytes()) {
            Ok(v) => v,
            Err(err) => {
                log::error!("Error decoding cookie from base64: {err}");

                return err_resp(next, req).await;
            },
        };
        let mut out = Vec::new();
        match flate2::bufread::GzDecoder::new(bytes.as_slice()).read_to_end(&mut out) {
            Ok(_) => {},
            Err(err) => {
                log::error!("Error decompressing cookie: {err}");
                return err_resp(next, req).await;
            },
        }

        match serde_json::from_slice(out.as_slice()) {
            Ok(v) => v,
            Err(err) => {
                log::error!("Error deserializing cookie: {err}, {out:?}");
                return err_resp(next, req).await;
            },
        }
    };
    let db = get_db().await;
    match Session::new(email.user_id, db).await {
        Ok(v) => {
            req.extensions_mut().insert(Some(v));
            next.call(req).await
        },
        Err(err) => {
            log::error!("Error creating session: {err}");
            struct Wrap(sqlx::Error);
            impl std::fmt::Debug for Wrap {
                fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                    <sqlx::Error as core::fmt::Debug>::fmt(&self.0, f)
                }
            }
            impl std::fmt::Display for Wrap {
                fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                    write!(f, "Error with Db lookup whilst creating session: {}", self.0)
                }
            }
            impl std::error::Error for Wrap {
                fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                    Some(&self.0)
                }
            }
            impl actix_web::ResponseError for Wrap {}

            Err(Wrap(err).into())
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
    <form action="/api/logout" method="POST">
        <input type="submit" value="Logout"></input>
    </form>
"#;
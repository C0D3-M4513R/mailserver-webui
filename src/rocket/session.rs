use std::io::Read;
use base64::Engine;
use rocket::Request;
use rocket::request::Outcome;

#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize, rocket::form::FromForm)]
pub struct Permission {
    domain_id: i64,
    is_owner: bool,
    domain_accepts_email: bool,
    domain_level: i64,
    admin: bool,
    view_domain: bool,
    modify_domain: bool,
    list_subdomain: bool,
    create_subdomain: bool,
    delete_subdomain: bool,
    list_accounts: bool,
    create_accounts: bool,
    modify_accounts: bool,
    delete_accounts: bool,
    create_alias: bool,
    modify_alias: bool,
    list_permissions: bool,
    manage_permissions: bool,
}

impl Permission {
    pub fn new(
        domain_id: i64,
        is_owner: bool,
        domain_accepts_email: bool,
        domain_level: i64,
        admin: bool,
        view_domain: bool,
        modify_domain: bool,
        list_subdomain: bool,
        create_subdomain: bool,
        delete_subdomain: bool,
        list_accounts: bool,
        create_accounts: bool,
        modify_accounts: bool,
        delete_accounts: bool,
        create_alias: bool,
        modify_alias: bool,
        list_permissions: bool,
        manage_permissions: bool,
    ) -> Self {
        Self {
            domain_id,
            is_owner,
            domain_accepts_email,
            domain_level,
            admin,
            view_domain,
            modify_domain,
            list_subdomain,
            create_subdomain,
            delete_subdomain,
            list_accounts,
            create_accounts,
            modify_accounts,
            delete_accounts,
            create_alias,
            modify_alias,
            list_permissions,
            manage_permissions,
        }
    }
    #[inline] pub const fn get_domain_id(&self) -> i64 { self.domain_id }
    #[inline] pub const fn get_is_owner(&self) -> bool { self.is_owner }
    #[inline] pub const fn get_domain_accepts_email(&self) -> bool { self.domain_accepts_email }
    #[inline] pub const fn get_domain_level(&self) -> i64 { self.domain_level }
    #[inline] pub const fn get_admin(&self) -> bool { self.get_is_owner() || self.admin }
    #[inline] pub const fn get_view_domain(&self) -> bool { self.get_is_owner() || self.view_domain }
    #[inline] pub const fn get_modify_domain(&self) -> bool { self.get_is_owner() || (self.view_domain && self.modify_domain) }
    #[inline] pub const fn get_list_subdomain(&self) -> bool { self.get_is_owner() || self.list_subdomain }
    #[inline] pub const fn get_create_subdomain(&self) -> bool { self.get_is_owner() || (self.view_domain && self.list_subdomain && self.create_subdomain) }
    #[inline] pub const fn get_delete_subdomain(&self) -> bool { self.get_is_owner() || (self.view_domain && self.list_subdomain && self.delete_subdomain) }
    #[inline] pub const fn get_list_accounts(&self) -> bool { self.get_is_owner() || self.list_accounts }
    #[inline] pub const fn get_create_accounts(&self) -> bool { self.get_is_owner() || (self.view_domain && self.list_accounts && self.create_accounts) }
    #[inline] pub const fn get_modify_accounts(&self) -> bool { self.get_is_owner() || (self.view_domain && self.list_accounts && self.modify_accounts) }
    #[inline] pub const fn get_delete_accounts(&self) -> bool { self.get_is_owner() || (self.view_domain && self.list_accounts && self.delete_accounts) }
    #[inline] pub const fn get_create_alias(&self) -> bool { self.get_is_owner() || self.create_alias }
    #[inline] pub const fn get_modify_alias(&self) -> bool { self.get_is_owner() || self.modify_alias }
    #[inline] pub const fn get_list_permissions(&self) -> bool { self.get_is_owner() || self.list_permissions }
    #[inline] pub const fn get_manage_permissions(&self) -> bool { self.get_is_owner() || (self.view_domain && self.list_permissions && self.manage_permissions) }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    user_id: i64,
    self_change_password: bool,
    permissions: std::collections::HashMap<String, Permission>,
}

impl Session{
    #[inline]
    pub async fn new(user_id: i64, self_change_password: bool) -> anyhow::Result<Self> {
        let db = crate::get_mysql().await;
        let permissions = sqlx::query!(r#"
SELECT
        domains.name as "domain!",
        perm.domain_id as "domain_id!",
        domains.accepts_email as "domain_accepts_email!",
        domains.level as "domain_level!",
        perm.admin as "admin!",
        perm.view_domain as "view_domain!",
        perm.modify_domain as "modify_domain!",
        perm.list_subdomain as "list_subdomain!",
        perm.create_subdomain as "create_subdomain!",
        perm.delete_subdomain as "delete_subdomain!",
        perm.list_accounts as "list_accounts!",
        perm.create_accounts as "create_accounts!",
        perm.delete_accounts as "delete_accounts!",
        perm.modify_accounts as "modify_accounts!",
        perm.create_alias as "create_alias!",
        perm.modify_alias as "modify_alias!",
        perm.list_permissions as "list_permissions!",
        perm.manage_permissions as "manage_permissions!",
        (domains.domain_owner = perm.user_id) as "is_owner!"
FROM flattened_web_domain_permissions perm
JOIN virtual_domains domains ON domains.id = perm.domain_id
        WHERE perm.user_id = $1"#, user_id)
            .fetch_all(db)
            .await;
        let permissions = permissions?;

        let permissions = permissions.into_iter().map(|v|
            (v.domain, super::session::Permission::new(
                v.domain_id,
                v.is_owner,
                v.domain_accepts_email,
                v.domain_level,
                v.admin,
                v.view_domain,
                v.modify_domain,
                v.list_subdomain,
                v.create_subdomain,
                v.delete_subdomain,
                v.list_accounts,
                v.create_accounts,
                v.modify_accounts,
                v.delete_accounts,
                v.create_alias,
                v.modify_alias,
                v.list_permissions,
                v.manage_permissions,
            ))
        ).collect::<std::collections::HashMap<_,_>>();

        Ok(Self {
            user_id,
            self_change_password,
            permissions,
        })
    }

    pub async fn refresh_permissions(&mut self, cookies: &rocket::http::CookieJar<'_>) -> anyhow::Result<()> {
        let session = Self::new(self.user_id, self.self_change_password).await?;
        match session.get_cookie() {
            Ok(v) => cookies.add_private(v),
            Err(err) => {
                Self::remove_cookie(cookies);
                #[cfg(debug_assertions)]
                log::error!("Error creating cookie: {err}");
                anyhow::bail!("Error creating cookie: {err}");
            }
        }
        self.permissions = session.permissions;
        self.self_change_password = session.self_change_password;
        Ok(())
    }
    pub fn remove_cookie(cookies: &rocket::http::CookieJar<'_>) {
        match cookies.get_private("email")  {
            Some(cookie) => cookies.remove_private(cookie),
            None => {},
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

    #[inline] pub const fn get_user_id(&self) -> i64 { self.user_id }
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
pub const HEADER:&str = const_format::formatcp!(
    r#"
        {LOGOUT}
        <form action="/admin/refresh_session" method="POST" onsubmit="() => location.reload()">
            <input type="submit" value="Refresh Permissions"></input>
        </form>
        <a href="/admin/change_pw">Change Password</a>
    "#,
);

const LOGOUT:&str = r#"
    <form action="/logout" method="POST">
        <input type="submit" value="Logout"></input>
    </form>
"#;
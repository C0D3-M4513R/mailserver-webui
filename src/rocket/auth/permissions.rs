use std::collections::HashMap;

#[derive(Debug, Default, Copy, Clone, serde::Serialize, serde::Deserialize, rocket::form::FromForm)]
pub struct Enabled<T> {
    pub enabled: bool,
    pub value: T,
}
macro_rules! get_perm {
    ($para:expr) => {{
        const NAME:&str = $para.to_string();
        match $para {
            Perm::ManagePermissions => {
                const_format::formatcp!(r#"CASE WHEN domains.domain_owner = input.user_id OR (slf.admin AND slf.manage_permissions)                              THEN input.manage_permissions  ELSE target.manage_permissions    END AS manage_permissions"#)
            },
            v => {
                const_format::formatcp!(r#"CASE WHEN domains.domain_owner = input.user_id OR (slf.manage_permissions AND (slf.admin OR slf.{NAME}))               THEN input.{NAME}               ELSE target.{NAME}                 END AS {NAME}"#)
            }
        }
    }};
}
macro_rules! get_bind {
    (@_impl, $lit:expr, $para:expr, $($param1:expr),+) => {{
        const A1:&str = get_bind!(@_impl, $lit, $para);
        const A2:&str = get_bind!(@_impl, $lit + 1, $($param1),+);
        const_format::concatcp!(A1, ",", A2)
    }};
    (@_impl, $lit:expr, $para:expr) => {
        {
            const NUM:i64 = $lit;
            const_format::concatcp!("CAST($", NUM," AS boolean[])")
        }
    };
    ($($para:expr),+) => { get_bind!(@_impl, 4, $($para),+) };
}
macro_rules! perms {
    () => {
perms!(_impl,
    Admin, admin,
    ViewDomain, view_domain,
    ModifyDomain, modify_domain,
    ListSubdomain, list_subdomain,
    CreateSubdomain, create_subdomain,
    DeleteSubdomain, delete_subdomain,
    ListAccounts, list_accounts,
    CreateAccounts, create_accounts,
    ModifyAccounts, modify_accounts,
    DeleteAccounts, delete_accounts,
    CreateAlias, create_alias,
    ModifyAlias, modify_alias,
    ListPermissions, list_permissions,
    ManagePermissions, manage_permissions
);
    };
    (_impl, $($param:ident, $ident:ident),+) => {
#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize, rocket::form::FromForm)]
pub struct Permission {
    domain_id: i64,
    is_owner: bool,
    domain_accepts_email: bool,
    domain_level: i64,
    $($ident : bool,)*
}
impl Permission {
    pub const fn new(
        domain_id: i64,
        is_owner: bool,
        domain_accepts_email: bool,
        domain_level: i64,
        $($ident : bool,)*
    ) -> Self {
        Self {
            domain_id,
            is_owner,
            domain_accepts_email,
            domain_level,
            $($ident,)*
        }
    }
    #[inline] pub const fn domain_id(&self) -> i64 { self.domain_id }
    #[inline] pub const fn is_owner(&self) -> bool { self.is_owner }
    #[inline] pub const fn domain_accepts_email(&self) -> bool { self.domain_accepts_email }
    #[inline] pub const fn domain_level(&self) -> i64 { self.domain_level }
    $(    #[inline] pub const fn $ident(&self) -> bool { self.is_owner() || self.$ident })*
}

#[derive(Debug, Default, Copy, Clone, serde::Serialize, serde::Deserialize, rocket::form::FromForm)]
pub struct OptPermission {
    $($ident : Option<bool>,)*
}
impl OptPermission{
    pub fn into_update_perms(self, target_user_id: i64) -> UpdatePermissions{
        let mut users = HashMap::with_capacity(1);
        users.insert(target_user_id, Enabled{enabled: true, value:self});
        UpdatePermissions{
            users,
        }
    }
}

#[derive(Debug, Default, Clone, rocket::form::FromForm)]
pub struct UpdatePermissions{
    pub users: HashMap<i64, Enabled<OptPermission>>,
}

impl UpdatePermissions {
    pub async fn apply_perms(&self, self_user_id: i64, domain_id:i64) -> Result<u64, sqlx::Error> {
        if self.users.is_empty() {
            return Ok(0);
        }
        let db = crate::get_mysql().await;
        let mut user_id = Vec::with_capacity(self.users.len());
        if user_id.is_empty() {
            return Ok(0);
        }
        $(let mut $ident = Vec::with_capacity(self.users.len());)+
        for (user_id_i, perms) in self.users.iter() {
            if !perms.enabled { continue;}
            user_id.push(*user_id_i);
            $($ident.push(perms.value.$ident);)+
        }
        let user_id = user_id;
        $(let $ident = $ident;)+
//1 = domain_id,
//2 = self_user_id
//3 = user ids
//4+ = permissions

        sqlx::query(QUERY)
            .bind(domain_id)
            .bind(self_user_id)
            .bind(user_id.as_slice())
    $(.bind($ident.as_slice()))+
        .execute(db)
        .await.map(|v|v.rows_affected())
    }
}

const QUERY:&str = {
    pub enum Perm {
        $($param,)*
    }
    impl Perm{
        pub const fn to_string(&self) -> &'static str {
            match self {
                $(Self::$param => stringify!($ident),)*
            }
        }
    }
    const QUERY_CASES: &str = const_format::concatcp!(
        $(get_perm!(Perm::$param), ",",)*
    );
    const QUERY_BINDS: &str = const_format::concatcp!(
        get_bind!($($param),+),
    );
    const_format::concatcp!(r#"
            MERGE INTO web_domain_permissions AS perm
    USING (
        WITH input AS (
            SELECT * FROM unnest(
            "#,
                QUERY_BINDS,
                r#"
                ,$3::bigint[]
              ) AS t(
                "#,
                $(stringify!($ident), ",",)+
                r#"
                user_id
            )
        ) SELECT
            input.user_id AS target_user_id,"#,QUERY_CASES,r#"
            $1 as domain_id
        FROM web_domain_permissions target
            JOIN input ON target.user_id = input.user_id
            JOIN flattened_web_domain_permissions slf ON slf.domain_id = $1 AND slf.user_id = $2
            JOIN domains ON domains.id = $1
        WHERE target.domain_id = $1
   ) AS row ON perm.domain_id = row.domain_id AND perm.user_id = row.target_user_id
WHEN MATCHED THEN
    UPDATE SET
    "#,
        $(stringify!($ident), " = row.", stringify!($ident), ",",)+
    r#"
        domain_id = row.domain_id,
        user_id = row.target_user_id
WHEN NOT MATCHED THEN
    INSERT (
    "#,
        $(stringify!($ident), ",",)+
    r#"
        domain_id,
        user_id
    ) VALUES (
"#, $("row.", stringify!($ident), ",",)+
"
       row.domain_id,
       row.target_user_id
)"
        )
        };
    };
}
perms!();
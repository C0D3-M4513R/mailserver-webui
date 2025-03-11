use quote::quote;

macro_rules! get_perm {
    (manage_permissions) => {
        r#"CASE WHEN input.self_id = ANY(domains.domain_owner) OR (slf.admin AND slf.manage_permissions)                              THEN input.manage_permissions  ELSE target.manage_permissions    END AS manage_permissions"#
    };
    ($para:expr) => {
        concat!(r#"CASE WHEN input.self_id = ANY(domains.domain_owner) OR (slf.manage_permissions AND (slf.admin OR slf."#, stringify!($para), "))               THEN input.", stringify!($para) , "               ELSE target.", stringify!($para) ,  "                 END AS " , stringify!($para))
    };
}
macro_rules! get_bind {
    (@_impl, $lit:expr, $para:expr, $($param1:expr),+) => {{
        const_format::concatcp!(get_bind!(@_impl, $lit, $para),",",get_bind!(@_impl, $lit + 1, $($param1),+))
    }};
    (@_impl, $lit:expr, $para:expr) => {{
        const NUM:u64 = $lit;
        const_format::concatcp!("$", NUM,"::boolean[]")
    }};
    ($($para:expr),+) => { get_bind!(@_impl, 4, $($para),+) };
}
macro_rules! perms {
    () => {
perms!(_impl,
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
    manage_permissions
)
    };
    (_impl, $($ident:ident),+) => {{
        perms!(_impl_set, $($ident),+)
    }};
    (_impl_set, $($ident:ident),+) => {{
        const QUERY:&str = {
            const QUERY_BINDS:&str = get_bind!($($ident),+);
            const QUERY_IDENTS:&str = concat!($(stringify!($ident) , "," , )+);

            const_format::concatcp!(r#"
MERGE INTO web_domain_permissions AS perm
    USING (
        WITH input AS (
            SELECT t.*, $2::bigint as self_id FROM unnest(
            "#,
                QUERY_BINDS,
                r#"
                ,$3::bigint[]
              ) AS t(
                "#,
                QUERY_IDENTS,
                r#"
                user_id
            )
        ) SELECT
            input.user_id AS target_user_id,"# , $(get_perm!($ident) , "," ,)* r#"
            slf.domain_id as domain_id
        FROM input
            JOIN virtual_domains domains ON domains.id = $1
            JOIN flattened_web_domain_permissions slf ON slf.domain_id = $1 AND slf.user_id = input.self_id
            LEFT JOIN web_domain_permissions target ON target.domain_id = domains.id AND target.user_id = input.user_id
   ) AS row ON perm.domain_id = row.domain_id AND perm.user_id = row.target_user_id
WHEN MATCHED THEN
    UPDATE SET
    "# ,
        $(stringify!($ident) , " = row." , stringify!($ident) ,  "," , )+
    r#"
        domain_id = row.domain_id,
        user_id = row.target_user_id
WHEN NOT MATCHED THEN
    INSERT (
    "# ,
        $(stringify!($ident) , "," , )+
    r#"
        domain_id,
        user_id
    ) VALUES (
"# , $("row." , stringify!($ident) , "," ,)+
"
       row.domain_id,
       row.target_user_id
)")
        };
        const GET_PERMISSION_QUERY:&str = const_format::concatcp!("SELECT ", $(" perm.", stringify!($ident), r#" as ""#, stringify!($ident), r#"!", "#, )+
r#"     domains.name as "domain!",
        perm.domain_id as "domain_id!",
        domains.accepts_email as "domain_accepts_email!",
        domains.level as "domain_level!",
        perm.user_id = ANY(domains.domain_owner) as "is_owner!"
FROM flattened_web_domain_permissions perm
JOIN virtual_domains domains ON domains.id = perm.domain_id
        WHERE perm.user_id = $1"#);
        quote!{
#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize, rocket::form::FromForm)]
pub struct Permission {
    domain_id: i64,
    is_owner: bool,
    domain_accepts_email: bool,
    domain_level: i64,
    $($ident : bool,)*
}
impl Session{

    #[inline]
    pub async fn new(user_id: i64, self_change_password: bool, pool: &sqlx::postgres::PgPool) -> anyhow::Result<Self> {
        let permissions = sqlx::query!(#GET_PERMISSION_QUERY, user_id)
            .fetch_all(pool)
            .await;
        let permissions = permissions?;

        let permissions = permissions.into_iter().map(|v|
            (v.domain, Permission::new(
                v.domain_id,
                v.is_owner,
                v.domain_accepts_email,
                v.domain_level,
                $(v.$ident,)+
            ))
        ).collect::<std::collections::HashMap<_,_>>();

        Ok(Self {
            user_id,
            self_change_password,
            permissions,
        })
    }
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
    pub async fn apply_perms(&self, self_user_id: i64, domain_id:i64, pool: &sqlx::postgres::PgPool) -> Result<u64, sqlx::Error> {
        ::log::debug!("Applying permissions for domain{domain_id} by user{self_user_id}: {self:?}");
        if self.users.is_empty() {
            return Ok(0);
        }
        let mut user_id = Vec::with_capacity(self.users.len());
        $(let mut $ident = Vec::with_capacity(self.users.len());)+
        for (user_id_i, perms) in self.users.iter() {
            if !perms.enabled { continue;}
            user_id.push(*user_id_i);
            $($ident.push(perms.value.$ident);)+
        }
        if user_id.is_empty() {
            return Ok(0);
        }
        let user_id = user_id;
        $(let $ident = $ident;)+
        ::log::debug!("Sending query for applying permissions for domain{domain_id} by user{self_user_id}");
//1 = domain_id,
//2 = self_user_id
//3 = user ids
//4+ = permissions
::sqlx::query_unchecked!(
        #QUERY,
domain_id,
self_user_id,
user_id.as_slice(),
$($ident.as_slice(),)+
        ).execute(pool).await.map(|v|v.rows_affected())
    }
}

    }}};
}

#[proc_macro]
pub fn query(_: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let v = perms!();
    v.into()
}
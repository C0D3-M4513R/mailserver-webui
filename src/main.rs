mod rocket;

const SPECIAL_ROOT_DOMAIN_NAME:&str = "root";

pub(crate) async fn get_mysql<'a>() -> &'a sqlx::postgres::PgPool {
    static MYSQL: tokio::sync::OnceCell<sqlx::postgres::PgPool> = tokio::sync::OnceCell::const_new();
    MYSQL.get_or_init(||async {
        let options = sqlx::postgres::PgConnectOptions::new();
        let pool = sqlx::Pool::connect_with(options).await.expect("Failed to connect to postgres");
        log::info!("Connected to postgres");
        pool
    }).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv()?;
    {
        use tracing_subscriber::Layer;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let registry = tracing_subscriber::registry();
        #[cfg(tokio_unstable)]
        let registry = registry.with(console_subscriber::spawn());
        registry.with(
            tracing_subscriber::fmt::layer()
                .pretty()
                .with_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        )
            .init();
        log::info!("Initialized logging");
    }

    let db = get_mysql().await;
// let r = sqlx::query!(r#"
// SELECT
//     user_id,
//     NULLIF(admin[0], admin[1]) AS admin,
// FROM (SELECT * FROM unnest(
//     $1::bigint[],
//     $2::bool[][]
//   ) AS t(
//     user_id,
//     admin
// ))
// "#, &[1, 2, 3], &[[false, true], [false, false], [true, false]]).fetch_all(db).await;
//     log::info!("r: {:?}", r);

    ::rocket::build()
        .mount("/", ::rocket::routes![
            rocket::index_get,
            rocket::index_post,
            rocket::logout_post,

            rocket::admin_get,
            rocket::admin_domain_get,
            rocket::admin_domain_name_put,
            rocket::admin_domain__accepts_email__put,
            rocket::admin_domain_owner_put,
            //Account Overview
            rocket::admin_domain_accounts_get,
            rocket::admin_domain_accounts_put,
            rocket::admin_domain_accounts_delete,
            //Single-Account Stuff
            rocket::admin_domain_account_get,
            rocket::admin_domain_account_delete,
            rocket::admin_domain_account_email_put,
            rocket::admin_domain_account_password_put,
            rocket::admin_domain_account_permissions_put,
            //Subdomain Overview
            rocket::admin_domain_subdomains_get,
            rocket::admin_domain_subdomains_put,
            rocket::admin_domain_subdomains_delete,
            //Permissions
            rocket::admin_domain_permissions_get,
            rocket::admin_domain_permissions_put,

            rocket::post_refresh_session,
            rocket::admin_get_change_pw,
            rocket::admin_put_change_pw,
        ])
        .launch()
        .await?;

    Ok(())
}
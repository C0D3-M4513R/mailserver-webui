mod rocket;


pub(crate) async fn get_mysql<'a>() -> &'a sqlx::postgres::PgPool {
    static MYSQL: tokio::sync::OnceCell<sqlx::postgres::PgPool> = tokio::sync::OnceCell::const_new();
    MYSQL.get_or_init(async || {
        let options = sqlx::postgres::PgConnectOptions::new();
        let pool = sqlx::Pool::connect_with(options).await.expect("Failed to connect to postgres");
        log::info!("Connected to postgres");
        pool
    }).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv()?;
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


    let _ = get_mysql().await;

    ::rocket::build()
        .mount("/", ::rocket::routes![
            rocket::index_get,
            rocket::index_post,
            rocket::logout_put,

            rocket::admin_get,
            rocket::admin_domain_get,
            rocket::admin_domain_accounts_get,
            rocket::admin_domain_accounts_put,
            rocket::admin_domain_accounts_delete,
            rocket::admin_domain_account_get,
            rocket::admin_domain_account_delete,
            rocket::admin_domain_account_email_put,
            rocket::admin_domain_account_password_put,

            rocket::post_refresh_session,
            rocket::admin_get_change_pw,
            rocket::admin_put_change_pw,
        ])
        .launch()
        .await?;

    Ok(())
}
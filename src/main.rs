mod rocket;


pub(crate) async fn get_mysql<'a>() -> &'a anyhow::Result<sqlx::postgres::PgPool> {
    static MYSQL: tokio::sync::OnceCell<anyhow::Result<sqlx::postgres::PgPool>> = tokio::sync::OnceCell::const_new();
    MYSQL.get_or_init(async || {
        let options = sqlx::postgres::PgConnectOptions::new();
        let pool = sqlx::Pool::connect_with(options).await?;
        log::info!("Connected to postgres");
        Ok(pool)
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


    let _ = match get_mysql().await{
        Ok(v) => v,
        Err(e) => anyhow::bail!("Failed to get mysql connection: {e}"),
    };

    ::rocket::build()
        .mount("/", ::rocket::routes![
            rocket::index::index_get,
            rocket::index::index_post,
            rocket::index::logout_post,

            rocket::admin::admin_get,
            rocket::admin::admin_domain_get,
        ])
        .launch()
        .await?;

    Ok(())
}
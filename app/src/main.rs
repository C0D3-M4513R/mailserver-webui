mod rocket;

const SPECIAL_ROOT_DOMAIN_NAME:&str = "root";
const WEBMAIL_DOMAIN:&str = "https://webmail.c0d3m4513r.com";
const MAIL_DOMAIN:&str = "mail.c0d3m4513r.com";
pub(crate) async fn get_db<'a>() -> sqlx::postgres::PgPool {
    static MYSQL: tokio::sync::OnceCell<sqlx::postgres::PgPool> = tokio::sync::OnceCell::const_new();
    MYSQL.get_or_init(||async {
        let options = sqlx::postgres::PgConnectOptions::new();
        let pool = sqlx::Pool::connect_with(options).await.expect("Failed to connect to postgres");
        log::info!("Connected to postgres");
        pool
    }).await.clone()
}
const FAIL2BAN_TARGET:&str = "fail2ban";
struct Fail2BanFilter;
impl<S>tracing_subscriber::layer::Filter<S> for Fail2BanFilter {
    fn enabled(&self, meta: &tracing::Metadata<'_>, _: &tracing_subscriber::layer::Context<'_, S>) -> bool {
        meta.target() == FAIL2BAN_TARGET
    }
    fn callsite_enabled(&self, meta: &'static tracing::Metadata<'static>) -> tracing::subscriber::Interest {
        if meta.target() == FAIL2BAN_TARGET {
            tracing::subscriber::Interest::always()
        } else {
            tracing::subscriber::Interest::never()
        }
    }
}

fn main() -> anyhow::Result<()> {
    dotenvy::dotenv()?;
    {
        let path = std::env::var_os("LOG_PATH").unwrap_or_else(|| "logs".to_string().into());
        let mut path = std::path::PathBuf::from(path);
        std::fs::create_dir_all(&path).expect("Failed to create log directory");
        path.push("rocket.log");
        let rocket_logfile = std::fs::File::create(&path).expect("Failed to create rocket log file");
        path.pop();
        path.push("fail2ban.log");
        let fail2ban_logfile = std::fs::File::create(&path).expect("Failed to create fail2ban log file");

        use tracing_subscriber::Layer;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let registry = tracing_subscriber::registry();
        #[cfg(tokio_unstable)]
        let registry = registry.with(console_subscriber::spawn());
        registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_thread_ids(true)
                    .with_thread_names(true)
                    .with_target(true)
                    .with_ansi(false)
                    .with_writer(rocket_logfile)
            )
            .with(
                tracing_subscriber::fmt::layer()
                    .with_thread_ids(true)
                    .with_thread_names(true)
                    .with_target(true)
                    .with_ansi(false)
                    .with_writer(fail2ban_logfile)
                    .with_filter(Fail2BanFilter{})
            )
            .with(
                tracing_subscriber::fmt::layer()
                    .pretty()
                    .with_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            )
            .init();
        log::info!("Initialized logging");
    }

    ::rocket::execute(launch())
}

async fn launch() -> anyhow::Result<()> {
    let _ = get_db().await;
 //    const Q_NULL: [bool;2] = [false, false];
 //    const Q_FALSE: [bool;2] = [false, true];
 //    const Q_TRUE: [bool;2] = [true, false];
 //    let input = vec![Q_NULL,Q_FALSE, Q_TRUE];
 // let r = sqlx::query!(r#"
 // SELECT
 //     user_id,
 //     admin
 // FROM (SELECT * FROM unnest(
 //     $1::bigint[],
 //     ARRAY(SELECT NULLIF(($2::boolean[][])[d1][1],($2::boolean[][])[d1][2]) FROM generate_subscripts(($2::boolean[][]), 1) as d1)
 //   ) AS t(
 //     user_id,
 //     admin
 // ))
 // "#, &[1, 2, 3], input.as_slice()).fetch_all(db).await;
 //     log::info!("r: {:?}", r);
 //
 //    let v = sqlx::query!(r#"Select ARRAY[null, false, true] as "test!""#)
 //        .fetch_one(get_mysql().await).await.expect("test");
 //    let test:Vec<Option<bool>> = v.test;

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
            rocket::admin_domain_accounts_delete_post,
            rocket::admin_domain_accounts_restore_post,
            //Single-Account Stuff
            rocket::admin_domain_account_get,
            rocket::admin_domain_account_delete,
            rocket::admin_domain_account_email_put,
            rocket::admin_domain_account_password_put,
            rocket::admin_domain_account_user_permission_put,
            rocket::admin_domain_account_permissions_put,
            rocket::admin_domain_account_aliases_delete,
            //Subdomain Overview
            rocket::admin_domain_subdomains_get,
            rocket::admin_domain_subdomains_put,
            rocket::admin_domain_subdomains_delete,
            rocket::admin_domain_subdomains_delete_post,
            rocket::admin_domain_subdomains_recover_post,
            //Permissions
            rocket::admin_domain_permissions_get,
            rocket::admin_domain_permissions_put,
            //Aliases
            rocket::admin_domain_aliases_get,
            rocket::admin_domain_aliases_delete,
            rocket::admin_domain_aliases_put,

            rocket::admin_get_change_pw,
            rocket::admin_put_change_pw,
        ])
        .launch()
        .await?;

    Ok(())
}
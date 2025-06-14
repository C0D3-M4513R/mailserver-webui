mod rocket;

//noinspection RsReplaceMatchExpr - unwrap_or is not a const_fn.
macro_rules! const_env {
    ($name:literal, $default:expr) => {
        match option_env!($name){ Some(v) => v, None => $default }
    };
}
pub const SPECIAL_ROOT_DOMAIN_NAME:&str = const_env!("SPECIAL_ROOT_DOMAIN_NAME","root");
pub const WEBMAIL_DOMAIN:&str = const_env!("WEBMAIL_DOMAIN", "https://webmail.c0d3m4513r.com");
pub const MAIL_DOMAIN:&str = const_env!("MAIL_DOMAIN", "mail.c0d3m4513r.com");
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
        .attach(CORS)
        .mount("/api", ::rocket::routes![
            //Auth
            rocket::index_post,
            rocket::auth_check_login,
            rocket::logout_post,

            //Domain Settings
            rocket::admin_domain_name_put,
            rocket::admin_domain__accepts_email__put,
            rocket::admin_domain_owner_put,
            //Domain Email Accounts
            rocket::admin_domain_accounts_put,
            rocket::admin_domain_accounts_delete,
            rocket::admin_domain_accounts_delete_post,
            rocket::admin_domain_accounts_restore_post,
            //Domain Email Account Settings
            rocket::admin_domain_account_delete,
            rocket::admin_domain_account_email_put,
            rocket::admin_domain_account_password_put,
            rocket::admin_domain_account_user_permission_put,
            rocket::admin_domain_account_permissions_put,
            rocket::admin_domain_account_aliases_delete,
            //Subdomain Settings
            rocket::admin_domain_subdomains_put,
            rocket::admin_domain_subdomains_delete,
            rocket::admin_domain_subdomains_delete_post,
            rocket::admin_domain_subdomains_recover_post,
            //Domain Email Aliases
            rocket::admin_domain_aliases_delete,
            rocket::admin_domain_aliases_put,
            //Domain Permissions
            rocket::admin_domain_permissions_put,
            //Account Settings
            rocket::admin_put_change_pw,
        ])
        .mount("/", ::rocket::routes![
            rocket::index_get,                      //login
            rocket::get_styles_css,                 //styles
            rocket::admin_get,                      //admin  dashboard
            rocket::admin_domain_get,               //domain dashboard
            rocket::admin_domain_accounts_get,      //Account Overview
            rocket::admin_domain_account_get,       //Single-Account Stuff
            rocket::admin_domain_subdomains_get,    //Subdomain Overview
            rocket::admin_domain_permissions_get,   //Permissions
            rocket::admin_domain_aliases_get,       //Aliases
            rocket::admin_get_change_pw,            //Account PW-Change
        ])
        .launch()
        .await?;

    Ok(())
}



pub struct CORS;

#[::rocket::async_trait]
impl ::rocket::fairing::Fairing for CORS {
    fn info(&self) -> ::rocket::fairing::Info {
        ::rocket::fairing::Info {
            name: "Add CORS headers to responses",
            kind: ::rocket::fairing::Kind::Response
        }
    }

    async fn on_response<'r>(&self, _request: &'r ::rocket::request::Request<'_>, response: &mut ::rocket::Response<'r>) {
        // response.set_header(::rocket::http::Header::new("Vary", "Sec-Fetch-Mode, Sec-Fetch-Site, Origin"));
        match _request.headers().get("Sec-Fetch-Mode").next() {
            Some("cors") => {},
            _ => return,
        }
        match _request.headers().get("Sec-Fetch-Site").next() {
            Some("cross-site") => {},
            _ => return,
        }
        match _request.headers().get("Origin").next() {
            Some("http://localhost:4200") => {},
            _ => return,
        }
        let methods = _request
            .rocket()
            .routes()
            .filter(|r|&r.uri.origin == _request.uri())
            .map(|r|r.method)
            .collect::<::std::collections::HashSet<_>>()
            .into_iter()
            .map(|v|v.as_str().to_string())
            .reduce(|mut a,b|{
                a.push(',');
                a.push(' ');
                a.push_str(b.as_str());
                a
            });
        let methods = match methods {
            None => return,
            Some(v) => v,
        };
        response.set_header(::rocket::http::Header::new("Access-Control-Allow-Methods", methods));
        response.set_header(::rocket::http::Header::new("Access-Control-Allow-Origin", "http://localhost:4200"));
        response.set_header(::rocket::http::Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(::rocket::http::Header::new("Access-Control-Allow-Credentials", "true"));
        if _request.method() == ::rocket::http::Method::Options {
            response.set_status(::rocket::http::Status::Ok);
        }
    }
}

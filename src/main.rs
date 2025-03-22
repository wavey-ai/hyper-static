use hyper_upload::server::HyperStatic;
use rustls::crypto::CryptoProvider;
use std::env;
use std::path::PathBuf;
use structopt::StructOpt;
use tracing_subscriber::{prelude::*, EnvFilter};

#[derive(Debug, StructOpt)]
#[structopt(name = "hyper-static")]
struct Command {
    #[structopt(long, default_value = "4433")]
    ssl_port: u16,

    #[structopt(long, env = "FULLCHAIN_PEM")]
    fullchain_pem: String,

    #[structopt(long, env = "PRIVKEY_PEM")]
    privkey_pem: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    const ENV_FILE: &str = include_str!("../.env");
    for line in ENV_FILE.lines() {
        if let Some((key, value)) = line.split_once('=') {
            env::set_var(key.trim(), value.trim());
        }
    }
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::Layer::default())
        .with(EnvFilter::new("info"));
    tracing::subscriber::set_global_default(subscriber)
        .expect("failed to set global default subscriber");

    let args = Command::from_args();
    let ssl_port = args.ssl_port;
    let privkey_pem = args.privkey_pem;
    let fullchain_pem = args.fullchain_pem;

    let path = PathBuf::from("./public/");

    let server = HyperStatic::new(fullchain_pem.clone(), privkey_pem.clone(), ssl_port, path);

    let (_up, fin, _shutdown) = server.start().await.expect("failed to start server");

    fin.await.expect("error on fin channel");

    Ok(())
}

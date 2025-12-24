use std::env;
use std::net::SocketAddr;

use axum::Router;
use dotenvy::dotenv;
use jsonwebtoken::DecodingKey;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

//mod ftp;
mod http;
mod rpc;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "INFO".into()),
        ))
        .with(
            tracing_subscriber::fmt::layer()
                .pretty()
                .with_writer(std::io::stdout)
                .with_target(false)
                .with_ansi(true)
                .with_line_number(false)
                .with_file(false),
        )
        .init();

    let mut jwt_pubkey = String::new();
    dotenv().ok();
    if let Ok(pubkey) = env::var("JWT_PUBKEY") {
        if !pubkey.trim().is_empty() {
            jwt_pubkey = pubkey;
        }
    } else if let Ok(pubkey) = std::fs::read_to_string("/etc/speedupdate/jwt_pubkey") {
        jwt_pubkey = pubkey;
    } else {
        tracing::error!("You have to create a .env file with JWT_PUBKEY key");
        std::process::exit(1);
    }

    let decoding_key = &DecodingKey::from_ed_pem(jwt_pubkey.as_bytes());
    let decoding_key = match decoding_key {
        Ok(key) => key,
        Err(err) => {
            tracing::error!("Unable to decode key: {}", err);
            std::process::exit(1);
        }
    };

    let addr = SocketAddr::from(([0, 0, 0, 0], 8012));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    let cors_layer = CorsLayer::new().allow_origin(Any).allow_headers(Any).expose_headers(Any);

    let grpc = rpc::rpc_api(decoding_key);
    let http = http::http_api();
    let app = Router::new().merge(grpc).merge(http).layer(cors_layer);

    tracing::info!("Speedupdate gRPC and http server listening on {addr}");

    axum::serve(listener, app).await.unwrap();

    //let ftp_server = tokio::spawn(ftp::start_ftp_server());
}

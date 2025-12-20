use std::net::SocketAddr;

use axum::Router;
use dotenvy::dotenv;
use jsonwebtoken::DecodingKey;
use ring::{
    rand,
    signature::{EcdsaKeyPair, KeyPair},
};
use std::env;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

//mod ftp;
mod http;
mod rpc;
//mod utils;

#[tokio::main]
async fn main() -> Result<(), String> {
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

    let mut jwt_pkey = String::new();
    dotenv().ok();
    if let Ok(pkey) = env::var("JWT_PKEY") {
        if !pkey.trim().is_empty() {
            jwt_pkey = pkey;
        }
    } else if let Ok(pkey) = std::fs::read_to_string("/etc/lucle/jwt_pkey") {
        jwt_pkey = pkey;
    } else {
        tracing::error!("You have to create a .env file with PKEY key");
        return Err("You have to create a .env file with PKEY key".to_string());
    }

    let rng = &rand::SystemRandom::new();
    let pair = match EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        jwt_pkey.as_bytes(),
        rng,
    ) {
        Ok(key) => key,
        Err(err) => {
            tracing::error!("Unable to create private key: {err}");
            return Err(format!("Unable to create private key: {}", err));
        }
    };

    let decoding_key = &DecodingKey::from_ec_der(pair.public_key().as_ref());

    let addr = SocketAddr::from(([0, 0, 0, 0], 8012));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    let cors_layer = CorsLayer::new().allow_origin(Any).allow_headers(Any).expose_headers(Any);

    let grpc = rpc::rpc_api(decoding_key);
    let http = http::http_api();
    let app = Router::new().merge(grpc).merge(http).layer(cors_layer);

    tracing::info!("Speedupdate gRPC and http server listening on {addr}");

    axum::serve(listener, app).await.unwrap();

    //let ftp_server = tokio::spawn(ftp::start_ftp_server());
    Ok(())
}

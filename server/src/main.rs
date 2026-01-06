use axum::Router;
use base64::{engine::general_purpose, Engine};
use dotenvy::dotenv;
use jsonwebtoken::DecodingKey;
use std::env;
use std::net::SocketAddr;
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

    dotenv().ok();
    let decoding_key = if let Ok(pubkey) = env::var("JWT_PUBKEY") {
        let der = general_purpose::STANDARD.decode(pubkey).unwrap();
        DecodingKey::from_ed_der(&der)
    } else if let Ok(pubkey) = std::fs::read_to_string("public.pem") {
        DecodingKey::from_ed_pem(pubkey.as_bytes()).unwrap()
    } else if let Ok(pubkey) = std::fs::read_to_string("/etc/speedupdate/jwt_pubkey") {
        DecodingKey::from_ed_pem(pubkey.as_bytes()).unwrap()
    } else {
        tracing::error!("You have to create a .env file with JWT_PUBKEY key");
        std::process::exit(1);
    };

    let addr = SocketAddr::from(([0, 0, 0, 0], 8012));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    let cors_layer = CorsLayer::new().allow_origin(Any).allow_headers(Any).expose_headers(Any);

    let grpc = rpc::rpc_api(&decoding_key);
    let http = http::http_api();
    let app = Router::new().merge(grpc).merge(http).layer(cors_layer);

    tracing::info!("Speedupdate gRPC and http server listening on {addr}");

    axum::serve(listener, app).await.unwrap();

    //let ftp_server = tokio::spawn(ftp::start_ftp_server());
}

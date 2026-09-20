use std::{
    convert::Infallible,
    fs,
    future::ready,
    io::{self, Read},
    path::{Path, PathBuf},
};

use axum::{
    extract::{DefaultBodyLimit, MatchedPath, Multipart, Path as AxumPath, Request},
    handler::HandlerWithoutStateExt,
    http::{header::CONTENT_LENGTH, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Router,
};
use futures::stream::Stream;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use tokio::time::{sleep, Duration};
use tokio::{
    fs::File,
    io::AsyncWriteExt,
    sync::broadcast::{self, Sender},
};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use zip::result::ZipError;

use crate::errors::SpeedupdateServerError;

fn extract_version(file_name: &str) -> Option<String> {
    // Split on '_' and find the first segment that looks like X.Y.Z
    file_name
        .split('_')
        .find(|segment| {
            let parts: Vec<&str> = segment.split('.').collect();
            parts.len() == 3 && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
        })
        .map(|s| s.to_string())
}

fn setup_metrics_recorder() -> PrometheusHandle {
    const EXPONENTIAL_SECONDS: &[f64] =
        &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

    PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("http_requests_duration_seconds".to_string()),
            EXPONENTIAL_SECONDS,
        )
        .unwrap()
        .install_recorder()
        .unwrap()
}

async fn track_metrics(req: Request, next: Next) -> impl IntoResponse {
    let path = if let Some(matched_path) = req.extensions().get::<MatchedPath>() {
        matched_path.as_str().to_owned()
    } else {
        req.uri().path().to_owned()
    };
    let method = req.method().clone();
    let response = next.run(req).await;
    let status = response.status().as_u16().to_string();
    let labels = [("method", method.to_string()), ("path", path), ("status", status)];
    metrics::counter!("http_requests_total", &labels).increment(1);
    response
}

async fn health_check() -> &'static str {
    "OK"
}

pub fn http_api() -> Router {
    let (progress_tx, _) = broadcast::channel(100);
    let recorder_handle = setup_metrics_recorder();

    async fn handle_404() -> (StatusCode, &'static str) {
        (StatusCode::NOT_FOUND, "Not found")
    }

    let serve_dir = ServeDir::new(".").not_found_service(handle_404.into_service());

    Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(move || ready(recorder_handle.render())))
        .route(
            "/{repo}/{type}/binaries/{platform}",
            post({
                let progress_tx = progress_tx.clone();
                move |headers, path, multipart| {
                    save_binaries(progress_tx.clone(), headers, path, multipart)
                }
            }),
        )
        .nest_service("/downloads", serve_dir)
        .route(
            "/{repo}/launcher",
            post({
                let progress_tx = progress_tx.clone();
                move |headers, path, multipart| {
                    save_image(progress_tx.clone(), headers, path, multipart)
                }
            }),
        )
        .route("/{repo}/{type}/progression", get(move || sse_handler(progress_tx)))
        .layer(DefaultBodyLimit::disable())
        .route_layer(middleware::from_fn(track_metrics))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
                .expose_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
}

async fn save_binaries(
    progress_tx: Sender<(usize, usize)>,
    headers: HeaderMap,
    AxumPath((repo, launcher_game, platform)): AxumPath<(String, String, String)>,
    multipart: Multipart,
) -> Result<(), SpeedupdateServerError> {
    let repo_path = PathBuf::from(&repo);

    if !repo_path.exists() || !repo_path.is_dir() {
        return Err(SpeedupdateServerError::RepositoryNotFound);
    }

    let total_size = parse_content_length(&headers)?;

    upload_versioned(
        progress_tx,
        multipart,
        total_size,
        &repo_path,
        &[&launcher_game, "binaries"],
        &platform,
    )
    .await
}

async fn save_image(
    progress_tx: Sender<(usize, usize)>,
    headers: HeaderMap,
    AxumPath(repo): AxumPath<String>,
    multipart: Multipart,
) -> Result<(), SpeedupdateServerError> {
    let repo_path = PathBuf::from(&repo);

    if !repo_path.exists() || !repo_path.is_dir() {
        return Err(SpeedupdateServerError::RepositoryNotFound);
    }

    let total_size = parse_content_length(&headers)?;

    upload_flat(progress_tx, multipart, total_size, &repo_path).await
}

fn parse_content_length(headers: &HeaderMap) -> Result<usize, SpeedupdateServerError> {
    let raw = headers
        .get(CONTENT_LENGTH)
        .ok_or(SpeedupdateServerError::MissingContentLength)?
        .to_str()
        .map_err(|e| SpeedupdateServerError::InvalidContentLength(e.to_string()))?;

    raw.parse::<usize>().map_err(|_| SpeedupdateServerError::InvalidContentLength(raw.to_string()))
}

async fn upload_versioned(
    progress_tx: Sender<(usize, usize)>,
    mut multipart: Multipart,
    total_size: usize,
    base_dir: &Path,
    path_segments: &[&str],
    platform: &str,
) -> Result<(), SpeedupdateServerError> {
    while let Some(mut field) = multipart.next_field().await? {
        let file_name =
            field.file_name().ok_or(SpeedupdateServerError::MissingFileName)?.to_string();

        let version = extract_version(&file_name)
            .ok_or_else(|| SpeedupdateServerError::MissingVersion(file_name.clone()))?;

        let upload_dir = path_segments
            .iter()
            .fold(base_dir.to_path_buf(), |acc, seg| acc.join(seg))
            .join(format!("{} {}", version, platform));

        fs::create_dir_all(&upload_dir)?;

        let file_path = upload_dir.join(&file_name);
        write_field(&mut field, &file_path, &progress_tx, total_size).await?;

        tracing::info!("File {} uploaded to {}", file_name, upload_dir.display());

        post_process(&file_path).await?;
    }

    Ok(())
}

async fn upload_flat(
    progress_tx: Sender<(usize, usize)>,
    mut multipart: Multipart,
    total_size: usize,
    upload_dir: &Path,
) -> Result<(), SpeedupdateServerError> {
    fs::create_dir_all(upload_dir)?;

    while let Some(mut field) = multipart.next_field().await? {
        let file_name =
            field.file_name().ok_or(SpeedupdateServerError::MissingFileName)?.to_string();

        let file_path = upload_dir.join(&file_name);
        write_field(&mut field, &file_path, &progress_tx, total_size).await?;

        tracing::info!("File {} uploaded to {}", file_name, upload_dir.display());

        post_process(&file_path).await?;
    }

    Ok(())
}

async fn write_field(
    field: &mut axum::extract::multipart::Field<'_>,
    dest: &Path,
    progress_tx: &Sender<(usize, usize)>,
    total_size: usize,
) -> Result<(), SpeedupdateServerError> {
    let mut file = File::create(dest).await?;
    let mut progression = 0usize;

    while let Some(chunk) = field.chunk().await? {
        progression += chunk.len();
        let _ = progress_tx.send((progression, total_size));
        file.write_all(&chunk).await?;
    }
    let _ = progress_tx.send((total_size, total_size));

    Ok(())
}

async fn post_process(file_path: &Path) -> Result<(), SpeedupdateServerError> {
    sleep(Duration::from_secs(2)).await;

    if is_zip_file(file_path)? {
        extract_zip(file_path)?;
        fs::remove_file(file_path)?;
    }

    Ok(())
}

async fn sse_handler(
    progress_tx: Sender<(usize, usize)>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = progress_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok((done, total)) => {
            let percent = done * 100 / total;
            Some(Ok(Event::default().data(percent.to_string())))
        }
        Err(_) => None,
    });

    Sse::new(stream)
}

fn is_zip_file(file_path: &Path) -> io::Result<bool> {
    let mut file = std::fs::File::open(file_path)?;
    let mut signature = [0u8; 4];
    file.read_exact(&mut signature)?;
    Ok(signature == [0x50, 0x4B, 0x03, 0x04])
}

fn extract_zip(zip_path: &Path) -> Result<(), ZipError> {
    let file = fs::File::open(zip_path).unwrap();
    let mut archive = zip::ZipArchive::new(file)?;
    // Extract alongside the zip (strip the extension to get the output dir)
    let out_dir = zip_path.with_extension("");

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).unwrap();

        let relative = match entry.enclosed_name() {
            Some(p) => p,
            None => continue,
        };

        let outpath = out_dir.join(relative);

        if !entry.comment().is_empty() {
            tracing::info!("Entry {i} comment: {}", entry.comment());
        }

        if entry.is_dir() {
            tracing::info!("Extracting dir  {} → {}", i, outpath.display());
            fs::create_dir_all(&outpath).unwrap();
        } else {
            tracing::info!(
                "Extracting file {} → {} ({} bytes)",
                i,
                outpath.display(),
                entry.size()
            );
            if let Some(parent) = outpath.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent).unwrap();
                }
            }
            let mut outfile = fs::File::create(&outpath).unwrap();
            io::copy(&mut entry, &mut outfile).unwrap();
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = entry.unix_mode() {
                fs::set_permissions(&outpath, fs::Permissions::from_mode(mode)).unwrap();
            }
        }
    }

    Ok(())
}

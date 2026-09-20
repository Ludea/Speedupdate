pub enum SpeedupdateServerError {
    MissingContentLength,
    InvalidContentLength(String),
    MissingFileName,
    MissingVersion(String),
    RepositoryNotFound,
    Io(std::io::Error),
    Multipart(axum::extract::multipart::MultipartError),
    Zip(zip::result::ZipError),
}

impl SpeedupdateServerError {
    fn status(&self) -> http::StatusCode {
        match self {
            SpeedupdateServerError::MissingContentLength
            | SpeedupdateServerError::InvalidContentLength(_)
            | SpeedupdateServerError::MissingFileName
            | SpeedupdateServerError::MissingVersion(_)
            | SpeedupdateServerError::RepositoryNotFound
            | SpeedupdateServerError::Multipart(_) => http::StatusCode::BAD_REQUEST,
            SpeedupdateServerError::Io(_) | SpeedupdateServerError::Zip(_) => {
                http::StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl std::fmt::Display for SpeedupdateServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpeedupdateServerError::MissingContentLength => {
                write!(f, "Missing Content-Length header")
            }
            SpeedupdateServerError::InvalidContentLength(s) => {
                write!(f, "Invalid Content-Length value: {}", s)
            }
            SpeedupdateServerError::MissingFileName => {
                write!(f, "Missing file name in multipart field")
            }
            SpeedupdateServerError::MissingVersion(name) => {
                write!(f, "Cannot extract version from filename: {}", name)
            }
            SpeedupdateServerError::RepositoryNotFound => write!(f, "No repository found"),
            SpeedupdateServerError::Io(e) => write!(f, "IO error: {}", e),
            SpeedupdateServerError::Multipart(e) => write!(f, "Multipart error: {}", e),
            SpeedupdateServerError::Zip(e) => write!(f, "Zip error: {}", e),
        }
    }
}

impl axum::response::IntoResponse for SpeedupdateServerError {
    fn into_response(self) -> axum::response::Response {
        (self.status(), self.to_string()).into_response()
    }
}

impl From<std::io::Error> for SpeedupdateServerError {
    fn from(e: std::io::Error) -> Self {
        SpeedupdateServerError::Io(e)
    }
}

impl From<zip::result::ZipError> for SpeedupdateServerError {
    fn from(e: zip::result::ZipError) -> Self {
        SpeedupdateServerError::Zip(e)
    }
}

impl From<axum::extract::multipart::MultipartError> for SpeedupdateServerError {
    fn from(e: axum::extract::multipart::MultipartError) -> Self {
        SpeedupdateServerError::Multipart(e)
    }
}

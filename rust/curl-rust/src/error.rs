use std::io;

pub type Result<T> = std::result::Result<T, CurlError>;

#[derive(Debug, thiserror::Error)]
pub enum CurlError {
    #[error("{0}")]
    Usage(String),
    #[error("unsupported option or feature: {0}")]
    Unsupported(String),
    #[error("URL using bad/illegal format or missing URL: {0}")]
    Url(String),
    #[error("failed to read or write local data: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    ReadError(String),
    #[error("transfer failed: {0}")]
    Transfer(String),
    #[error("IPFS automatic gateway detection failed")]
    IpfsGatewayDetection,
    #[error("{0}")]
    BadFunctionArgument(String),
    #[error("Maximum ({max}) redirects followed")]
    TooManyRedirects { max: usize },
    #[error("HTTP response code said error: {status}")]
    HttpStatus { status: u16 },
    #[error("Operation timed out")]
    Timeout,
}

impl CurlError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) | Self::Unsupported(_) => 2,
            Self::Url(_) => 3,
            Self::Transfer(_) => 7,
            Self::TooManyRedirects { .. } => 47,
            Self::HttpStatus { .. } => 22,
            Self::Io(_) => 23,
            Self::ReadError(_) => 26,
            Self::Timeout => 28,
            Self::IpfsGatewayDetection => 37,
            Self::BadFunctionArgument(_) => 43,
        }
    }
}

pub trait ResultExt<T> {
    fn transfer_err(self) -> Result<T>;
}

impl<T> ResultExt<T> for reqwest::Result<T> {
    fn transfer_err(self) -> Result<T> {
        self.map_err(|error| CurlError::Transfer(error.to_string()))
    }
}

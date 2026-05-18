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
    #[error("weird server reply")]
    WeirdServerReply,
    #[error("remote access denied")]
    RemoteAccessDenied,
    #[error("IPFS automatic gateway detection failed")]
    IpfsGatewayDetection,
    #[error("{0}")]
    BadFunctionArgument(String),
    #[error("Maximum ({max}) redirects followed")]
    TooManyRedirects { max: usize },
    #[error("HTTP response code said error: {status}")]
    HttpStatus { status: u16 },
    #[error("Maximum file size exceeded")]
    FileSizeExceeded,
    #[error("Login denied")]
    LoginDenied,
    #[error("failed sending data to the peer")]
    SendError,
    #[error("TFTP file not found")]
    TftpNotFound,
    #[error("TFTP permission problem")]
    TftpPermission,
    #[error("TFTP disk full")]
    TftpDiskFull,
    #[error("TFTP illegal operation")]
    TftpIllegal,
    #[error("TFTP unknown transfer ID")]
    TftpUnknownId,
    #[error("TFTP file already exists")]
    TftpFileExists,
    #[error("TFTP no such user")]
    TftpNoSuchUser,
    #[error("Operation timed out")]
    Timeout,
}

impl CurlError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) | Self::Unsupported(_) => 2,
            Self::Url(_) => 3,
            Self::Transfer(_) => 7,
            Self::WeirdServerReply => 8,
            Self::RemoteAccessDenied => 9,
            Self::TooManyRedirects { .. } => 47,
            Self::HttpStatus { .. } => 22,
            Self::FileSizeExceeded => 63,
            Self::LoginDenied => 67,
            Self::SendError => 55,
            Self::TftpNotFound => 68,
            Self::TftpPermission => 69,
            Self::TftpDiskFull => 70,
            Self::TftpIllegal => 71,
            Self::TftpUnknownId => 72,
            Self::TftpFileExists => 73,
            Self::TftpNoSuchUser => 74,
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

use std::io;

pub type Result<T> = std::result::Result<T, CurlError>;

#[derive(Debug, thiserror::Error)]
pub enum CurlError {
    #[error("{0}")]
    Usage(String),
    #[error(
        "You can only select one HTTP request method! You asked for both PUT (-T, --upload-file) and POST (-d, --data)."
    )]
    HttpMethodConflict,
    #[error("bad option syntax: {0}")]
    OptionSyntax(String),
    #[error("Could not parse CURLOPT_RESOLVE entry '{0}'")]
    ResolveParse(String),
    #[error("No valid port number in '{0}'")]
    ConnectToPortSyntax(String),
    #[error("unsupported option or feature: {0}")]
    Unsupported(String),
    #[error("Protocol \"{0}\" not supported")]
    UnsupportedProtocol(String),
    #[error("URL using bad/illegal format or missing URL: {0}")]
    Url(String),
    #[error("failed to read or write local data: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    ReadError(String),
    #[error("transfer failed: {0}")]
    Transfer(String),
    #[error("transferred a partial file")]
    PartialFile,
    #[error("weird server reply")]
    WeirdServerReply,
    #[error("server returned nothing")]
    GotNothing,
    #[error("failure when receiving data from the peer")]
    RecvError,
    #[error("FTP weird PASV reply")]
    FtpWeirdPasvReply,
    #[error("FTP could not set transfer type")]
    FtpCouldntSetType,
    #[error("FTP could not retrieve file")]
    FtpCouldntRetrFile,
    #[error("FTP upload failed")]
    FtpUploadFailed,
    #[error("FTP: command REST failed")]
    FtpCouldntUseRest,
    #[error("remote access denied")]
    RemoteAccessDenied,
    #[error("quote command failed")]
    QuoteError,
    #[error("IPFS automatic gateway detection failed")]
    IpfsGatewayDetection,
    #[error("Couldn't read a file:// file: {0}")]
    FileCouldntReadFile(String),
    #[error("{0}")]
    BadFunctionArgument(String),
    #[error("Maximum ({max}) redirects followed")]
    TooManyRedirects { max: usize },
    #[error("HTTP response code said error: {status}")]
    HttpStatus { status: u16 },
    #[error("HTTP server does not seem to support byte ranges. Cannot resume.")]
    RangeError,
    #[error("Cannot resume transfer")]
    BadDownloadResume,
    #[error("Maximum file size exceeded")]
    FileSizeExceeded,
    #[error("Remote disk full")]
    RemoteDiskFull,
    #[error("Login denied")]
    LoginDenied,
    #[error("URL rejected: Credentials was passed in the URL when prohibited")]
    UrlCredentialsProhibited,
    #[error("SSL peer certificate or SSH remote key was not OK")]
    PeerVerificationFailed,
    #[error("LDAP cannot bind")]
    LdapCannotBind,
    #[error("LDAP search failed")]
    LdapSearchFailed,
    #[error("Remote file not found")]
    RemoteFileNotFound,
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
    #[error("RTSP CSeq mismatch or invalid CSeq")]
    RtspCseqError,
    #[error("Operation timed out")]
    Timeout,
}

impl CurlError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::UnsupportedProtocol(_) => 1,
            Self::Usage(_) | Self::HttpMethodConflict | Self::Unsupported(_) => 2,
            Self::Url(_) => 3,
            Self::OptionSyntax(_) | Self::ResolveParse(_) | Self::ConnectToPortSyntax(_) => 49,
            Self::Transfer(_) => 7,
            Self::PartialFile => 18,
            Self::WeirdServerReply => 8,
            Self::GotNothing => 52,
            Self::RecvError => 56,
            Self::RemoteAccessDenied => 9,
            Self::FtpWeirdPasvReply => 13,
            Self::FtpCouldntSetType => 17,
            Self::FtpCouldntRetrFile => 19,
            Self::FtpUploadFailed => 25,
            Self::FtpCouldntUseRest => 31,
            Self::QuoteError => 21,
            Self::TooManyRedirects { .. } => 47,
            Self::HttpStatus { .. } => 22,
            Self::RangeError => 33,
            Self::BadDownloadResume => 36,
            Self::FileSizeExceeded => 63,
            Self::RemoteDiskFull => 70,
            Self::LoginDenied | Self::UrlCredentialsProhibited => 67,
            Self::PeerVerificationFailed => 60,
            Self::LdapCannotBind => 38,
            Self::LdapSearchFailed => 39,
            Self::RemoteFileNotFound => 78,
            Self::SendError => 55,
            Self::TftpNotFound => 68,
            Self::TftpPermission => 69,
            Self::TftpDiskFull => 70,
            Self::TftpIllegal => 71,
            Self::TftpUnknownId => 72,
            Self::TftpFileExists => 73,
            Self::TftpNoSuchUser => 74,
            Self::RtspCseqError => 85,
            Self::Io(_) => 23,
            Self::ReadError(_) => 26,
            Self::Timeout => 28,
            Self::IpfsGatewayDetection | Self::FileCouldntReadFile(_) => 37,
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

pub mod cli;
pub mod data;
pub mod error;
pub mod glob;
pub mod output;
pub mod transfer;
pub mod writeout;

pub use cli::{Config, TransferConfig, parse_args};
pub use error::{CurlError, ResultExt};

pub async fn run(config: Config) -> Result<i32, CurlError> {
    if config.show_help {
        cli::print_help();
        return Ok(0);
    }

    if config.show_version {
        cli::print_version();
        return Ok(0);
    }

    transfer::run(config).await
}

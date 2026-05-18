pub mod cli;
pub mod data;
pub mod error;
pub mod glob;
pub mod output;
pub mod transfer;
pub mod writeout;

mod cookie;
mod ipfs;
mod libcurl;

pub use cli::{Config, TransferConfig, parse_args};
pub use error::{CurlError, ResultExt};

pub async fn run(config: Config) -> Result<i32, CurlError> {
    if config.show_help {
        cli::print_help(config.help_category.as_deref());
        return Ok(0);
    }

    if config.show_version {
        cli::print_version();
        return Ok(0);
    }

    let result = transfer::run(config.clone()).await;
    if let Some(path) = &config.libcurl
        && let Err(error) = libcurl::write_source(path, &config)
    {
        eprintln!("curl: warning: failed to write --libcurl output: {error}");
    }
    result
}

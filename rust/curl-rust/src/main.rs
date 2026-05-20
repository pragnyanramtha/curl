use std::io::Write as _;

use curl_rust::{CurlError, parse_args};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(path) = curl_rust::cli::stderr_redirect_target(&args)
        && let Err(error) = redirect_stderr(&path)
    {
        eprintln!("Warning: Failed to open {path}: {error}");
    }

    let config = match parse_args(args) {
        Ok(config) => config,
        Err(error) => exit(error),
    };

    match curl_rust::run(config).await {
        Ok(code) => std::process::exit(code),
        Err(error) => exit(error),
    }
}

fn exit(error: CurlError) -> ! {
    eprintln!("curl: {error}");
    std::process::exit(error.exit_code());
}

#[cfg(unix)]
fn redirect_stderr(path: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;

    std::io::stderr().flush()?;
    let result = if path == "-" {
        unsafe { libc::dup2(libc::STDOUT_FILENO, libc::STDERR_FILENO) }
    } else {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        unsafe { libc::dup2(file.as_raw_fd(), libc::STDERR_FILENO) }
    };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn redirect_stderr(_path: &str) -> std::io::Result<()> {
    Ok(())
}

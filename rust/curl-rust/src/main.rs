use curl_rust::{CurlError, parse_args};

#[tokio::main]
async fn main() {
    let config = match parse_args(std::env::args().skip(1)) {
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

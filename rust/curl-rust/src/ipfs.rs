use std::path::PathBuf;

use url::Url;

use crate::error::{CurlError, Result};

pub fn maybe_rewrite_url(input: &str, configured_gateway: Option<&str>) -> Result<Option<String>> {
    let Some(protocol) = ipfs_protocol(input) else {
        return Ok(None);
    };

    let input_url = Url::parse(input).map_err(|_| malformed_target())?;
    let cid = input_url.host_str().ok_or_else(malformed_target)?;
    let gateway = gateway_url(configured_gateway)?;

    if gateway.query().is_some() {
        return Err(malformed_target());
    }

    let gateway_path = gateway.path();
    let input_path = match input_url.path() {
        "" | "/" => "",
        path => path,
    };
    let mut path = String::new();
    if gateway_path != "/" {
        path.push_str(gateway_path.trim_end_matches('/'));
    }
    path.push('/');
    path.push_str(protocol);
    path.push('/');
    path.push_str(cid);
    path.push_str(input_path);

    let mut rewritten = gateway;
    rewritten.set_path(&path);
    rewritten.set_query(input_url.query());
    rewritten.set_fragment(None);
    Ok(Some(rewritten.to_string()))
}

fn ipfs_protocol(input: &str) -> Option<&'static str> {
    let (scheme, _) = input.split_once(':')?;
    if scheme.eq_ignore_ascii_case("ipfs") {
        Some("ipfs")
    } else if scheme.eq_ignore_ascii_case("ipns") {
        Some("ipns")
    } else {
        None
    }
}

fn gateway_url(configured_gateway: Option<&str>) -> Result<Url> {
    if let Some(gateway) = configured_gateway {
        return parse_explicit_gateway(gateway);
    }

    let gateway = detect_gateway()?;
    Url::parse(&gateway).map_err(|_| malformed_target())
}

fn parse_explicit_gateway(gateway: &str) -> Result<Url> {
    let candidate = if gateway.contains("://") {
        gateway.to_string()
    } else {
        format!("http://{gateway}")
    };
    Url::parse(&candidate).map_err(|_| {
        CurlError::BadFunctionArgument("--ipfs-gateway was given a malformed URL".to_string())
    })
}

fn detect_gateway() -> Result<String> {
    if let Ok(gateway) = std::env::var("IPFS_GATEWAY") {
        return Ok(gateway);
    }

    let ipfs_path = if let Some(path) = std::env::var_os("IPFS_PATH") {
        PathBuf::from(path)
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".ipfs")
    } else {
        return Err(CurlError::IpfsGatewayDetection);
    };

    let text = std::fs::read_to_string(ipfs_path.join("gateway"))
        .map_err(|_| CurlError::IpfsGatewayDetection)?;
    let gateway = text
        .split(['\n', '\r'])
        .next()
        .unwrap_or_default()
        .to_string();
    if gateway.is_empty() {
        return Err(CurlError::IpfsGatewayDetection);
    }
    Ok(gateway)
}

fn malformed_target() -> CurlError {
    CurlError::Url("malformed target URL".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_ipfs_url_to_gateway_path() {
        let rewritten = maybe_rewrite_url(
            "ipfs://bafy/a/b?foo=bar&aaa=bbb",
            Some("http://example.com/some/path"),
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            rewritten,
            "http://example.com/some/path/ipfs/bafy/a/b?foo=bar&aaa=bbb"
        );
    }

    #[test]
    fn rewrites_ipns_url_to_gateway_path() {
        let rewritten = maybe_rewrite_url("ipns://fancy.tld/", Some("http://example.com"))
            .unwrap()
            .unwrap();

        assert_eq!(rewritten, "http://example.com/ipns/fancy.tld");
    }

    #[test]
    fn rejects_gateway_queries() {
        let error = maybe_rewrite_url("ipfs://bafy", Some("http://example.com/some/path?biz=baz"))
            .unwrap_err();

        assert_eq!(error.exit_code(), 3);
    }
}

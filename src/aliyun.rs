use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::blocking::Client;
use serde_json::Value;
use sha1::Sha1;

use crate::cli::StsArgs;
use crate::config::AliyunConfig;

const STS_VERSION: &str = "2015-04-01";

type HmacSha1 = Hmac<Sha1>;

pub fn assume_role(aliyun: &AliyunConfig, args: &StsArgs) -> Result<Value> {
    let access_key_id = required(
        aliyun.access_key_id.as_deref(),
        "missing Aliyun access key ID; set aliyun.access_key_id, ALIYUN_ACCESS_KEY_ID, or ALIBABA_CLOUD_ACCESS_KEY_ID",
    )?;
    let access_key_secret = required(
        aliyun.access_key_secret.as_deref(),
        "missing Aliyun access key secret; set aliyun.access_key_secret, ALIYUN_ACCESS_KEY_SECRET, or ALIBABA_CLOUD_ACCESS_KEY_SECRET",
    )?;

    let role_arn = required(
        Some(&args.role_arn),
        "missing Aliyun role ARN; pass --role-arn",
    )?;
    let role_session_name = required(
        Some(&args.role_session_name),
        "missing Aliyun role session name; pass --role-session-name",
    )?;
    let endpoint = required(
        Some(&args.endpoint),
        "missing Aliyun STS endpoint; pass --endpoint",
    )?;

    let mut params = BTreeMap::new();
    params.insert("AccessKeyId", access_key_id.to_owned());
    params.insert("Action", "AssumeRole".to_owned());
    params.insert("DurationSeconds", args.duration.as_secs().to_string());
    params.insert("Format", "JSON".to_owned());
    params.insert("RoleArn", role_arn.to_owned());
    params.insert("RoleSessionName", role_session_name.to_owned());
    params.insert("SignatureMethod", "HMAC-SHA1".to_owned());
    params.insert("SignatureNonce", nonce());
    params.insert("SignatureVersion", "1.0".to_owned());
    params.insert(
        "Timestamp",
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    );
    params.insert("Version", STS_VERSION.to_owned());

    if let Some(external_id) = args.external_id.as_deref() {
        params.insert("ExternalId", external_id.to_owned());
    }
    if let Some(policy) = args.policy.as_deref() {
        params.insert("Policy", policy.to_owned());
    }

    let signature = sign(&params, access_key_secret)?;
    let url = signed_url(endpoint, &params, &signature);
    let response = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to create HTTP client")?
        .get(url)
        .send()
        .context("failed to call Aliyun STS")?;
    let status = response.status();
    let body = response
        .text()
        .context("failed to read Aliyun STS response")?;

    if !status.is_success() {
        return Err(sts_error(status, &body));
    }

    serde_json::from_str(&body).context("Aliyun STS returned invalid JSON")
}

fn required<'a>(value: Option<&'a str>, message: &str) -> Result<&'a str> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .with_context(|| message.to_owned())
}

fn sign(params: &BTreeMap<&str, String>, access_key_secret: &str) -> Result<String> {
    let canonical = params
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let string_to_sign = format!("GET&{}&{}", encode("/"), encode(&canonical));
    let mut mac = HmacSha1::new_from_slice(format!("{access_key_secret}&").as_bytes())
        .context("invalid Aliyun access key secret")?;
    mac.update(string_to_sign.as_bytes());
    Ok(BASE64.encode(mac.finalize().into_bytes()))
}

fn signed_url(endpoint: &str, params: &BTreeMap<&str, String>, signature: &str) -> String {
    let endpoint = endpoint.trim_end_matches('/');
    let endpoint = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_owned()
    } else {
        format!("https://{endpoint}")
    };
    let mut query = params
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>();
    query.push(format!("Signature={}", encode(signature)));

    format!("{endpoint}/?{}", query.join("&"))
}

fn sts_error(status: reqwest::StatusCode, body: &str) -> anyhow::Error {
    let detail = serde_json::from_str::<Value>(body).ok().map(|value| {
        let code = value.get("Code").and_then(Value::as_str);
        let message = value.get("Message").and_then(Value::as_str);
        let request_id = value.get("RequestId").and_then(Value::as_str);
        match (code, message, request_id) {
            (Some(code), Some(message), Some(request_id)) => {
                format!("{code}: {message} (RequestId: {request_id})")
            }
            (Some(code), Some(message), None) => format!("{code}: {message}"),
            _ => body.to_owned(),
        }
    });

    anyhow::anyhow!(
        "Aliyun STS request failed with HTTP {status}: {}",
        detail.unwrap_or_else(|| body.to_owned())
    )
}

fn nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{nanos:x}-{:x}", std::process::id())
}

fn encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encoding_follows_aliyun_rules() {
        assert_eq!(encode("a b+c/"), "a%20b%2Bc%2F");
        assert_eq!(encode("AZaz09-_.~"), "AZaz09-_.~");
        assert_eq!(encode("中文"), "%E4%B8%AD%E6%96%87");
    }

    #[test]
    fn signature_is_base64_hmac_sha1() {
        let mut params = BTreeMap::new();
        params.insert("AccessKeyId", "testid".to_owned());
        params.insert("Action", "AssumeRole".to_owned());
        params.insert(
            "RoleArn",
            "acs:ram::1234567890123456:role/example".to_owned(),
        );

        let signature = sign(&params, "testsecret").unwrap();

        assert_eq!(signature, "U2KagmiPhBGLh5dvFvMFc5nDKkQ=");
    }

    #[test]
    fn missing_required_credentials_fail() {
        let aliyun = AliyunConfig::default();
        let args = StsArgs {
            endpoint: "sts.aliyuncs.com".to_owned(),
            role_arn: "acs:ram::1234567890123456:role/example".to_owned(),
            role_session_name: "cloud".to_owned(),
            duration: Duration::from_secs(3600),
            external_id: None,
            policy: None,
        };

        let error = assume_role(&aliyun, &args).unwrap_err();

        assert!(error.to_string().contains("missing Aliyun access key ID"));
    }
}

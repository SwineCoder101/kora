#![cfg(test)]

use anyhow::{Context, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::common::{
    constants::{TEST_APP_CHECK_APP_ID, TEST_APP_CHECK_PROJECT_NUMBER},
    harness::workspace_path,
};

/// The key pair kora-lib's unit tests sign with; `jwks.json` is its public half.
const APP_CHECK_FIXTURES: &str = "crates/lib/src/tests/fixtures/app_check";
const APP_CHECK_KEY_ID: &str = "kora-test-key";

/// Stands in for Firebase's JWKS endpoint and returns its URL.
///
/// It runs on a plain thread because Kora fetches the key set lazily, on the
/// first token it has to verify, and a server spawned on a `#[tokio::test]`
/// runtime would be gone once that test returned.
pub fn serve_app_check_jwks() -> Result<String> {
    let path = workspace_path(APP_CHECK_FIXTURES).join("jwks.json");
    let jwks = fs::read_to_string(&path)
        .with_context(|| format!("failed to read JWKS fixture {}", path.display()))?;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}/v1/jwks", listener.local_addr()?);

    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            // Every request gets the key set, so the request head is read only to clear it.
            let _ = stream.read(&mut [0u8; 2048]);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{jwks}",
                jwks.len()
            );
        }
    });

    Ok(url)
}

/// The claims of a token the app-check fixture accepts. Tests break one field at a time.
pub struct AppCheckClaims {
    pub project_number: String,
    pub app_id: String,
    /// Seconds from now; negative for a token that has already expired.
    pub expires_in: i64,
}

impl Default for AppCheckClaims {
    fn default() -> Self {
        Self {
            project_number: TEST_APP_CHECK_PROJECT_NUMBER.to_string(),
            app_id: TEST_APP_CHECK_APP_ID.to_string(),
            expires_in: 3600,
        }
    }
}

pub fn create_app_check_token(claims: AppCheckClaims) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let project_number = claims.project_number;

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(APP_CHECK_KEY_ID.to_string());

    let pem = fs::read(workspace_path(APP_CHECK_FIXTURES).join("signing-key.pem"))
        .expect("App Check signing key fixture should be readable");
    let key = EncodingKey::from_rsa_pem(&pem).expect("App Check signing key should parse");

    encode(
        &header,
        &json!({
            "iss": format!("https://firebaseappcheck.googleapis.com/{project_number}"),
            "aud": [format!("projects/{project_number}")],
            "sub": claims.app_id,
            "iat": now,
            "exp": now + claims.expires_in,
        }),
        &key,
    )
    .expect("App Check test token should sign")
}

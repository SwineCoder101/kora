use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mockito::{Mock, Server};
use serde_json::{json, Value};

use crate::constant::APP_CHECK_ISSUER_PREFIX;

pub const TEST_PROJECT_NUMBER: &str = "1234567890";
pub const TEST_APP_ID: &str = "1:1234567890:android:0123456789abcdef";
pub const TEST_KEY_ID: &str = "kora-test-key";

// A throwaway key pair that signs nothing outside these tests. `jwks.json` is its public half.
const SIGNING_KEY_PEM: &str = include_str!("fixtures/app_check/signing-key.pem");
const JWKS: &str = include_str!("fixtures/app_check/jwks.json");

/// The JWKS endpoint, not yet registered, so a test can attach an expected hit count first.
pub fn jwks_mock(server: &mut Server) -> Mock {
    server.mock("GET", "/v1/jwks").with_header("content-type", "application/json").with_body(JWKS)
}

/// Builds App Check tokens signed by the test key. The defaults describe a token the verifier
/// accepts for `TEST_PROJECT_NUMBER`; each setter breaks one property of it.
pub struct AppCheckTokenBuilder {
    kid: Option<String>,
    typ: Option<String>,
    issuer: String,
    audience: Vec<String>,
    app_id: String,
    expires_in: i64,
}

impl Default for AppCheckTokenBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AppCheckTokenBuilder {
    pub fn new() -> Self {
        Self {
            kid: Some(TEST_KEY_ID.to_string()),
            typ: Some("JWT".to_string()),
            issuer: format!("{APP_CHECK_ISSUER_PREFIX}{TEST_PROJECT_NUMBER}"),
            audience: vec![format!("projects/{TEST_PROJECT_NUMBER}")],
            app_id: TEST_APP_ID.to_string(),
            expires_in: 3600,
        }
    }

    pub fn kid(mut self, kid: Option<&str>) -> Self {
        self.kid = kid.map(str::to_string);
        self
    }

    pub fn typ(mut self, typ: Option<&str>) -> Self {
        self.typ = typ.map(str::to_string);
        self
    }

    pub fn issuer(mut self, issuer: &str) -> Self {
        self.issuer = issuer.to_string();
        self
    }

    pub fn audience(mut self, audience: &[&str]) -> Self {
        self.audience = audience.iter().map(|a| a.to_string()).collect();
        self
    }

    pub fn app_id(mut self, app_id: &str) -> Self {
        self.app_id = app_id.to_string();
        self
    }

    /// Seconds from now; negative for a token that has already expired.
    pub fn expires_in(mut self, seconds: i64) -> Self {
        self.expires_in = seconds;
        self
    }

    pub fn claims(&self) -> Value {
        let now = chrono::Utc::now().timestamp();
        json!({
            "iss": self.issuer,
            "aud": self.audience,
            "sub": self.app_id,
            "iat": now,
            "exp": now + self.expires_in,
        })
    }

    pub fn build(&self) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = self.kid.clone();
        header.typ = self.typ.clone();

        let key = EncodingKey::from_rsa_pem(SIGNING_KEY_PEM.as_bytes())
            .expect("test signing key should parse");
        encode(&header, &self.claims(), &key).expect("test token should sign")
    }
}

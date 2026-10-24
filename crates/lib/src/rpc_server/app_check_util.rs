use crate::{
    constant::{
        APP_CHECK_ISSUER_PREFIX, APP_CHECK_JWKS_CACHE_TTL_SECS,
        APP_CHECK_JWKS_MIN_REFRESH_INTERVAL_SECS, APP_CHECK_JWKS_TIMEOUT_SECS, APP_CHECK_JWKS_URL,
    },
    sanitize_error,
};
use jsonwebtoken::{decode, decode_header, jwk::Jwk, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};

#[derive(Debug, Error)]
pub enum AppCheckError {
    #[error("malformed token: {0}")]
    MalformedToken(String),
    #[error("unexpected token header: {0}")]
    UnexpectedHeader(&'static str),
    #[error("no JWKS key matches the token's key id")]
    UnknownKey,
    #[error("token rejected: {0}")]
    InvalidToken(String),
    #[error("app is not listed in app_check_app_ids")]
    AppNotAllowed,
    #[error("JWKS unavailable: {0}")]
    Jwks(String),
}

impl AppCheckError {
    /// A failure on Kora's side of the exchange rather than a bad token from the caller.
    pub fn is_jwks_failure(&self) -> bool {
        matches!(self, AppCheckError::Jwks(_))
    }
}

#[derive(Deserialize)]
struct AppCheckClaims {
    /// The Firebase app ID the token was minted for.
    sub: String,
}

#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<serde_json::Value>,
}

#[derive(Default)]
struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
    attempted_at: Option<Instant>,
}

impl JwksCache {
    fn is_fresh(&self) -> bool {
        self.fetched_at
            .is_some_and(|at| at.elapsed() < Duration::from_secs(APP_CHECK_JWKS_CACHE_TTL_SECS))
    }

    fn can_refresh(&self) -> bool {
        self.attempted_at.is_none_or(|at| {
            at.elapsed() >= Duration::from_secs(APP_CHECK_JWKS_MIN_REFRESH_INTERVAL_SECS)
        })
    }

    /// An expired set answers nothing: once the keys cannot be confirmed with the issuer, tokens
    /// stop verifying rather than being accepted against keys that may have been rotated out.
    fn lookup(&self, kid: &str) -> Option<DecodingKey> {
        if self.is_fresh() {
            self.keys.get(kid).cloned()
        } else {
            None
        }
    }
}

struct Inner {
    app_ids: Vec<String>,
    jwks_url: String,
    validation: Validation,
    client: Client,
    jwks: RwLock<JwksCache>,
    refresh: Mutex<()>,
}

/// Verifies Firebase App Check tokens against the project's published signing keys.
#[derive(Clone)]
pub struct AppCheckVerifier {
    inner: Arc<Inner>,
}

impl AppCheckVerifier {
    pub fn new(project_number: &str, app_ids: Vec<String>, jwks_url: Option<String>) -> Self {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[format!("projects/{project_number}")]);
        validation.set_issuer(&[format!("{APP_CHECK_ISSUER_PREFIX}{project_number}")]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);

        Self {
            inner: Arc::new(Inner {
                app_ids,
                jwks_url: jwks_url.unwrap_or_else(|| APP_CHECK_JWKS_URL.to_string()),
                validation,
                client: Client::new(),
                jwks: RwLock::new(JwksCache::default()),
                refresh: Mutex::new(()),
            }),
        }
    }

    /// Returns the Firebase app ID the token attests.
    pub async fn verify(&self, token: &str) -> Result<String, AppCheckError> {
        let header =
            decode_header(token).map_err(|e| AppCheckError::MalformedToken(e.to_string()))?;

        // Firebase signs App Check tokens with RS256 only. Refusing everything else before a key
        // is chosen rules out algorithm confusion.
        if header.alg != Algorithm::RS256 {
            return Err(AppCheckError::UnexpectedHeader("alg is not RS256"));
        }
        if header.typ.as_deref() != Some("JWT") {
            return Err(AppCheckError::UnexpectedHeader("typ is not JWT"));
        }
        let kid = header.kid.ok_or(AppCheckError::UnexpectedHeader("kid is missing"))?;

        let key = self.decoding_key(&kid).await?;
        let claims = decode::<AppCheckClaims>(token, &key, &self.inner.validation)
            .map_err(|e| AppCheckError::InvalidToken(e.to_string()))?
            .claims;

        if claims.sub.is_empty() {
            return Err(AppCheckError::InvalidToken("sub is empty".to_string()));
        }
        if !self.inner.app_ids.is_empty() && !self.inner.app_ids.contains(&claims.sub) {
            return Err(AppCheckError::AppNotAllowed);
        }

        Ok(claims.sub)
    }

    async fn decoding_key(&self, kid: &str) -> Result<DecodingKey, AppCheckError> {
        if let Some(key) = self.inner.jwks.read().await.lookup(kid) {
            return Ok(key);
        }

        // Concurrent misses queue here instead of each fetching the key set. The cache lock is
        // not held across the fetch, so tokens signed by a known key keep verifying meanwhile.
        let _refresh = self.inner.refresh.lock().await;
        {
            let mut cache = self.inner.jwks.write().await;
            if let Some(key) = cache.lookup(kid) {
                return Ok(key);
            }
            if !cache.can_refresh() {
                return Err(if cache.is_fresh() {
                    AppCheckError::UnknownKey
                } else {
                    AppCheckError::Jwks("last fetch failed, retrying shortly".to_string())
                });
            }
            cache.attempted_at = Some(Instant::now());
        }

        let keys = self.fetch_jwks().await?;

        let mut cache = self.inner.jwks.write().await;
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        cache.lookup(kid).ok_or(AppCheckError::UnknownKey)
    }

    async fn fetch_jwks(&self) -> Result<HashMap<String, DecodingKey>, AppCheckError> {
        let response = self
            .inner
            .client
            .get(&self.inner.jwks_url)
            .timeout(Duration::from_secs(APP_CHECK_JWKS_TIMEOUT_SECS))
            .send()
            .await
            .map_err(|e| AppCheckError::Jwks(format!("request failed: {}", sanitize_error!(e))))?;

        let status = response.status();
        if !status.is_success() {
            return Err(AppCheckError::Jwks(format!("endpoint returned {}", status.as_u16())));
        }

        let body: JwksResponse = response.json().await.map_err(|e| {
            AppCheckError::Jwks(format!("unreadable response: {}", sanitize_error!(e)))
        })?;

        // Entries are parsed one at a time so that a key this build cannot use does not discard
        // the rest of the set.
        let keys: HashMap<String, DecodingKey> = body
            .keys
            .into_iter()
            .filter_map(|entry| {
                let jwk: Jwk = serde_json::from_value(entry).ok()?;
                let kid = jwk.common.key_id.clone()?;
                let key = DecodingKey::from_jwk(&jwk).ok()?;
                Some((kid, key))
            })
            .collect();

        if keys.is_empty() {
            return Err(AppCheckError::Jwks("response holds no usable keys".to_string()));
        }

        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::app_check_mock::{
        jwks_mock, AppCheckTokenBuilder, TEST_APP_ID, TEST_KEY_ID, TEST_PROJECT_NUMBER,
    };
    use jsonwebtoken::{EncodingKey, Header};
    use mockito::Server;

    fn verifier(server: &Server, app_ids: &[&str]) -> AppCheckVerifier {
        AppCheckVerifier::new(
            TEST_PROJECT_NUMBER,
            app_ids.iter().map(|id| id.to_string()).collect(),
            Some(format!("{}/v1/jwks", server.url())),
        )
    }

    /// Puts the cache in the state it reaches once the TTL has run out. The timestamps are
    /// cleared rather than rewound because `Instant` cannot go back past boot on a fresh host.
    async fn expire_cache(verifier: &AppCheckVerifier) {
        let mut cache = verifier.inner.jwks.write().await;
        cache.fetched_at = None;
        cache.attempted_at = None;
    }

    #[tokio::test]
    async fn test_valid_token_returns_app_id() {
        let mut server = Server::new_async().await;
        let _jwks = jwks_mock(&mut server).create_async().await;

        let app_id = verifier(&server, &[]).verify(&AppCheckTokenBuilder::new().build()).await;

        assert_eq!(app_id.unwrap(), TEST_APP_ID);
    }

    #[tokio::test]
    async fn test_audience_listing_several_projects_is_accepted() {
        let mut server = Server::new_async().await;
        let _jwks = jwks_mock(&mut server).create_async().await;

        // Firebase lists the project under both its number and its ID.
        let token = AppCheckTokenBuilder::new()
            .audience(&[&format!("projects/{TEST_PROJECT_NUMBER}"), "projects/kora-test"])
            .build();

        assert!(verifier(&server, &[]).verify(&token).await.is_ok());
    }

    #[tokio::test]
    async fn test_expired_token_is_rejected() {
        let mut server = Server::new_async().await;
        let _jwks = jwks_mock(&mut server).create_async().await;

        let token = AppCheckTokenBuilder::new().expires_in(-3600).build();
        let result = verifier(&server, &[]).verify(&token).await;

        assert!(matches!(result, Err(AppCheckError::InvalidToken(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_token_for_another_project_is_rejected() {
        let mut server = Server::new_async().await;
        let _jwks = jwks_mock(&mut server).create_async().await;
        let verifier = verifier(&server, &[]);

        let wrong_audience = AppCheckTokenBuilder::new().audience(&["projects/999"]).build();
        let wrong_issuer =
            AppCheckTokenBuilder::new().issuer(&format!("{APP_CHECK_ISSUER_PREFIX}999")).build();

        for token in [wrong_audience, wrong_issuer] {
            let result = verifier.verify(&token).await;
            assert!(matches!(result, Err(AppCheckError::InvalidToken(_))), "got {result:?}");
        }
    }

    #[tokio::test]
    async fn test_app_id_allow_list() {
        let mut server = Server::new_async().await;
        let _jwks = jwks_mock(&mut server).create_async().await;
        let token = AppCheckTokenBuilder::new().build();

        assert!(verifier(&server, &[TEST_APP_ID]).verify(&token).await.is_ok());

        let result = verifier(&server, &["1:1234567890:ios:other"]).verify(&token).await;
        assert!(matches!(result, Err(AppCheckError::AppNotAllowed)), "got {result:?}");
    }

    #[tokio::test]
    async fn test_tampered_payload_is_rejected() {
        let mut server = Server::new_async().await;
        let _jwks = jwks_mock(&mut server).create_async().await;

        // Graft the payload of a token for another app onto a validly signed token.
        let signed = AppCheckTokenBuilder::new().build();
        let other = AppCheckTokenBuilder::new().app_id("1:1234567890:ios:attacker").build();
        let (signed, other): (Vec<&str>, Vec<&str>) =
            (signed.split('.').collect(), other.split('.').collect());
        let forged = format!("{}.{}.{}", signed[0], other[1], signed[2]);

        let result = verifier(&server, &[]).verify(&forged).await;
        assert!(matches!(result, Err(AppCheckError::InvalidToken(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_hs256_token_is_rejected_without_fetching_keys() {
        let mut server = Server::new_async().await;
        let jwks = jwks_mock(&mut server).expect(0).create_async().await;

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(TEST_KEY_ID.to_string());
        let token = jsonwebtoken::encode(
            &header,
            &AppCheckTokenBuilder::new().claims(),
            &EncodingKey::from_secret(b"attacker-chosen-secret"),
        )
        .unwrap();

        let result = verifier(&server, &[]).verify(&token).await;

        assert!(matches!(result, Err(AppCheckError::UnexpectedHeader(_))), "got {result:?}");
        jwks.assert_async().await;
    }

    #[tokio::test]
    async fn test_malformed_token_is_rejected() {
        let server = Server::new_async().await;
        let verifier = verifier(&server, &[]);

        for token in ["", "not-a-jwt", "a.b.c"] {
            let result = verifier.verify(token).await;
            assert!(matches!(result, Err(AppCheckError::MalformedToken(_))), "got {result:?}");
        }
    }

    #[tokio::test]
    async fn test_missing_kid_and_wrong_typ_are_rejected() {
        let server = Server::new_async().await;
        let verifier = verifier(&server, &[]);

        let no_kid = AppCheckTokenBuilder::new().kid(None).build();
        let wrong_typ = AppCheckTokenBuilder::new().typ(Some("at+jwt")).build();

        for token in [no_kid, wrong_typ] {
            let result = verifier.verify(&token).await;
            assert!(matches!(result, Err(AppCheckError::UnexpectedHeader(_))), "got {result:?}");
        }
    }

    #[tokio::test]
    async fn test_jwks_is_fetched_once_and_cached() {
        let mut server = Server::new_async().await;
        let jwks = jwks_mock(&mut server).expect(1).create_async().await;
        let verifier = verifier(&server, &[]);

        for _ in 0..3 {
            verifier.verify(&AppCheckTokenBuilder::new().build()).await.unwrap();
        }

        jwks.assert_async().await;
    }

    #[tokio::test]
    async fn test_unknown_kid_refetch_is_throttled() {
        let mut server = Server::new_async().await;
        let jwks = jwks_mock(&mut server).expect(1).create_async().await;
        let verifier = verifier(&server, &[]);

        verifier.verify(&AppCheckTokenBuilder::new().build()).await.unwrap();

        for _ in 0..3 {
            let token = AppCheckTokenBuilder::new().kid(Some("rotated-out")).build();
            let result = verifier.verify(&token).await;
            assert!(matches!(result, Err(AppCheckError::UnknownKey)), "got {result:?}");
        }

        // The known key keeps working, and none of the misses reached the endpoint.
        verifier.verify(&AppCheckTokenBuilder::new().build()).await.unwrap();
        jwks.assert_async().await;
    }

    #[tokio::test]
    async fn test_jwks_outage_fails_closed() {
        let mut server = Server::new_async().await;
        let unavailable =
            server.mock("GET", "/v1/jwks").with_status(503).expect(1).create_async().await;
        let verifier = verifier(&server, &[]);
        let token = AppCheckTokenBuilder::new().build();

        // The second attempt lands inside the refresh floor and must not accept the token either.
        for _ in 0..2 {
            let result = verifier.verify(&token).await;
            assert!(result.as_ref().is_err_and(AppCheckError::is_jwks_failure), "got {result:?}");
        }
        unavailable.assert_async().await;
    }

    #[tokio::test]
    async fn test_expired_cache_is_not_trusted_during_outage() {
        let mut server = Server::new_async().await;
        let jwks = jwks_mock(&mut server).create_async().await;
        let verifier = verifier(&server, &[]);
        let token = AppCheckTokenBuilder::new().build();

        verifier.verify(&token).await.unwrap();

        jwks.remove_async().await;
        let _unavailable = server.mock("GET", "/v1/jwks").with_status(503).create_async().await;
        expire_cache(&verifier).await;

        let result = verifier.verify(&token).await;
        assert!(result.as_ref().is_err_and(AppCheckError::is_jwks_failure), "got {result:?}");
    }

    #[tokio::test]
    async fn test_expired_cache_is_refreshed() {
        let mut server = Server::new_async().await;
        let jwks = jwks_mock(&mut server).expect(2).create_async().await;
        let verifier = verifier(&server, &[]);
        let token = AppCheckTokenBuilder::new().build();

        verifier.verify(&token).await.unwrap();
        expire_cache(&verifier).await;
        verifier.verify(&token).await.unwrap();

        jwks.assert_async().await;
    }

    #[tokio::test]
    async fn test_jwks_without_usable_keys_is_a_jwks_failure() {
        let mut server = Server::new_async().await;
        let _empty = server
            .mock("GET", "/v1/jwks")
            .with_body(r#"{"keys":[{"kty":"unsupported","kid":"kora-test-key"}]}"#)
            .create_async()
            .await;

        let result = verifier(&server, &[]).verify(&AppCheckTokenBuilder::new().build()).await;
        assert!(result.as_ref().is_err_and(AppCheckError::is_jwks_failure), "got {result:?}");
    }

    // Verifies a token Firebase really issued, against Firebase's real key set. Register a debug
    // token in the Firebase console (App Check > Apps > Manage debug tokens), then run with:
    //   FIREBASE_PROJECT_NUMBER=... FIREBASE_APP_ID=... APP_CHECK_DEBUG_TOKEN=... \
    //     cargo test -p kora-lib --lib app_check_live -- --ignored
    // Set FIREBASE_API_KEY as well if the project's API key is restricted.
    #[tokio::test]
    #[ignore]
    async fn test_app_check_live_debug_token_verifies() {
        let env = |name: &str| {
            std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set to run this test"))
        };
        let project_number = env("FIREBASE_PROJECT_NUMBER");
        let app_id = env("FIREBASE_APP_ID");
        let debug_token = env("APP_CHECK_DEBUG_TOKEN");

        let mut exchange = Client::new()
            .post(format!(
                "https://firebaseappcheck.googleapis.com/v1/projects/{project_number}/apps/{app_id}:exchangeDebugToken"
            ))
            .json(&serde_json::json!({ "debugToken": debug_token }));
        if let Ok(api_key) = std::env::var("FIREBASE_API_KEY") {
            exchange = exchange.header("x-goog-api-key", api_key);
        }
        let exchange: serde_json::Value = exchange
            .send()
            .await
            .expect("debug token exchange request failed")
            .json()
            .await
            .expect("debug token exchange returned no JSON");
        let token = exchange["token"]
            .as_str()
            .unwrap_or_else(|| panic!("debug token exchange was refused: {exchange}"));

        let verified = AppCheckVerifier::new(&project_number, vec![app_id.clone()], None)
            .verify(token)
            .await
            .expect("a Firebase-issued token should verify against Firebase's JWKS");
        assert_eq!(verified, app_id);

        let other_project = AppCheckVerifier::new("1", vec![], None).verify(token).await;
        assert!(
            matches!(other_project, Err(AppCheckError::InvalidToken(_))),
            "got {other_project:?}"
        );
    }
}

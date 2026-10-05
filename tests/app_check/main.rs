// App Check tests for Kora RPC server
//
// CONFIG: Uses tests/src/common/fixtures/app-check-test.toml (App Check is the only credential)
// TESTS: Firebase App Check attestation middleware
//        - Token verification via x-firebase-appcheck header against a JWKS endpoint
//        - Project, app ID, expiry and signature enforcement
//        - Liveness endpoint bypass (unauthenticated health checks)

mod app_check_auth;

// Make common utilities available
#[path = "../src/common/mod.rs"]
mod common;

use common::{harness_context, KoraSpec, TestContext};

pub async fn ctx() -> TestContext {
    harness_context(KoraSpec {
        config: "tests/src/common/fixtures/app-check-test.toml",
        signers: "tests/src/common/fixtures/signers.toml",
        initialize_payments_atas: false,
    })
    .await
}

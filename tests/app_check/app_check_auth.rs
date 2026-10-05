use crate::common::*;
use kora_lib::constant::X_FIREBASE_APPCHECK;

async fn request_with_token(server_url: &str, token: &str) -> reqwest::Response {
    make_auth_request(server_url, Some(vec![(X_FIREBASE_APPCHECK, token)])).await
}

/// Test App Check with a token for the configured project and app
#[tokio::test]
async fn test_app_check_valid_token() {
    let ctx = crate::ctx().await;

    let token = create_app_check_token(AppCheckClaims::default());
    let response = request_with_token(&ctx.client.server_url, &token).await;

    assert!(
        response.status().is_success(),
        "Valid App Check token should return 200, got {}",
        response.status()
    );
}

/// Test App Check with no token (should fail)
#[tokio::test]
async fn test_app_check_missing_token() {
    let ctx = crate::ctx().await;

    let response = make_auth_request(&ctx.client.server_url, None).await;

    assert_eq!(response.status(), 401, "Missing App Check token should return 401");
}

/// Test App Check with a value that is not a JWT (should fail)
#[tokio::test]
async fn test_app_check_malformed_token() {
    let ctx = crate::ctx().await;

    let response = request_with_token(&ctx.client.server_url, "not-a-jwt").await;

    assert_eq!(response.status(), 401, "Malformed App Check token should return 401");
}

/// Test App Check with an expired token (should fail)
#[tokio::test]
async fn test_app_check_expired_token() {
    let ctx = crate::ctx().await;

    let token =
        create_app_check_token(AppCheckClaims { expires_in: -3600, ..AppCheckClaims::default() });
    let response = request_with_token(&ctx.client.server_url, &token).await;

    assert_eq!(response.status(), 401, "Expired App Check token should return 401");
}

/// Test App Check with a correctly signed token for a different Firebase project (should fail)
#[tokio::test]
async fn test_app_check_token_for_another_project() {
    let ctx = crate::ctx().await;

    let token = create_app_check_token(AppCheckClaims {
        project_number: "999999".to_string(),
        ..AppCheckClaims::default()
    });
    let response = request_with_token(&ctx.client.server_url, &token).await;

    assert_eq!(response.status(), 401, "Token for another project should return 401");
}

/// Test App Check with a correctly signed token for an app outside app_check_app_ids (should fail)
#[tokio::test]
async fn test_app_check_app_not_in_allow_list() {
    let ctx = crate::ctx().await;

    let token = create_app_check_token(AppCheckClaims {
        app_id: "1:1234567890:ios:unlisted".to_string(),
        ..AppCheckClaims::default()
    });
    let response = request_with_token(&ctx.client.server_url, &token).await;

    assert_eq!(response.status(), 401, "Token for an unlisted app should return 401");
}

/// Test App Check with a token whose payload was swapped after signing (should fail)
#[tokio::test]
async fn test_app_check_forged_signature() {
    let ctx = crate::ctx().await;

    // An expired token doctored to look current: the valid token's payload, the old signature.
    let expired =
        create_app_check_token(AppCheckClaims { expires_in: -3600, ..AppCheckClaims::default() });
    let valid = create_app_check_token(AppCheckClaims::default());
    let (expired, valid): (Vec<&str>, Vec<&str>) =
        (expired.split('.').collect(), valid.split('.').collect());
    let forged = format!("{}.{}.{}", expired[0], valid[1], expired[2]);

    let response = request_with_token(&ctx.client.server_url, &forged).await;

    assert_eq!(response.status(), 401, "Token with a forged signature should return 401");
}

/// Test that liveness endpoint bypasses App Check
#[tokio::test]
async fn test_liveness_bypasses_app_check() {
    let ctx = crate::ctx().await;

    let client = reqwest::Client::new();
    let liveness_response = client
        .get(format!("{}/liveness", ctx.client.server_url))
        .send()
        .await
        .expect("Liveness request should succeed");

    assert!(
        liveness_response.status().is_success(),
        "Liveness should bypass App Check, got {}",
        liveness_response.status()
    );
}

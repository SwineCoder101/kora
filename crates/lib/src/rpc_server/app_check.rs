use crate::{
    constant::X_FIREBASE_APPCHECK,
    rpc_server::{
        app_check_util::AppCheckVerifier,
        auth::{auth_rejection_response, is_liveness_request},
        middleware_utils::extract_parts_and_body_bytes,
    },
    sanitize_error,
};
use http::{Request, Response};
use jsonrpsee::server::logger::Body;

#[derive(Clone)]
pub struct AppCheckLayer {
    verifier: AppCheckVerifier,
}

impl AppCheckLayer {
    pub fn new(verifier: AppCheckVerifier) -> Self {
        Self { verifier }
    }
}

impl<S> tower::Layer<S> for AppCheckLayer {
    type Service = AppCheckService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AppCheckService { inner, verifier: self.verifier.clone() }
    }
}

#[derive(Clone)]
pub struct AppCheckService<S> {
    inner: S,
    verifier: AppCheckVerifier,
}

impl<S> tower::Service<Request<Body>> for AppCheckService<S>
where
    S: tower::Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let verifier = self.verifier.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let (parts, body_bytes) = extract_parts_and_body_bytes(request).await;

            // Bypass auth for liveness endpoint
            if is_liveness_request(&body_bytes) {
                return inner.call(Request::from_parts(parts, Body::from(body_bytes))).await;
            }

            let request = Request::from_parts(parts, Body::from(body_bytes));
            let token = request.headers().get(X_FIREBASE_APPCHECK).and_then(|v| v.to_str().ok());

            let token = match token {
                Some(token) if !token.is_empty() => token,
                _ => return Ok(auth_rejection_response()),
            };

            if let Err(e) = verifier.verify(token).await {
                if e.is_jwks_failure() {
                    log::error!("App Check key set unavailable: {}", sanitize_error!(e));
                } else {
                    log::warn!("App Check token rejected: {}", sanitize_error!(e));
                }
                return Ok(auth_rejection_response());
            }

            inner.call(request).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        rpc_server::auth::RejectionReason,
        tests::app_check_mock::{jwks_mock, AppCheckTokenBuilder, TEST_PROJECT_NUMBER},
    };
    use http::{Method, StatusCode};
    use mockito::Server;
    use std::{
        future::Ready,
        task::{Context, Poll},
    };
    use tower::{Layer, Service, ServiceExt};

    #[derive(Clone)]
    struct MockService;

    impl tower::Service<Request<Body>> for MockService {
        type Response = Response<Body>;
        type Error = std::convert::Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: Request<Body>) -> Self::Future {
            std::future::ready(Ok(Response::builder().status(200).body(Body::empty()).unwrap()))
        }
    }

    const SIGN_BODY: &str = r#"{"jsonrpc":"2.0","method":"signTransaction","id":1}"#;

    fn test_service(server: &Server) -> AppCheckService<MockService> {
        let verifier = AppCheckVerifier::new(
            TEST_PROJECT_NUMBER,
            vec![],
            Some(format!("{}/v1/jwks", server.url())),
        );
        AppCheckLayer::new(verifier).layer(MockService)
    }

    fn request(body: &'static str, token: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method(Method::POST).uri("/");
        if let Some(token) = token {
            builder = builder.header(X_FIREBASE_APPCHECK, token);
        }
        builder.body(Body::from(body)).unwrap()
    }

    fn assert_auth_rejection(response: &Response<Body>) {
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.extensions().get::<RejectionReason>(),
            Some(&RejectionReason::AuthFailure)
        );
    }

    #[tokio::test]
    async fn test_app_check_layer_accepts_valid_token() {
        let mut server = Server::new_async().await;
        let _jwks = jwks_mock(&mut server).create_async().await;
        let mut service = test_service(&server);

        let token = AppCheckTokenBuilder::new().build();
        let response =
            service.ready().await.unwrap().call(request(SIGN_BODY, Some(&token))).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_app_check_layer_guards_read_only_methods_too() {
        let mut server = Server::new_async().await;
        let _jwks = jwks_mock(&mut server).create_async().await;
        let mut service = test_service(&server);

        let body = r#"{"jsonrpc":"2.0","method":"getConfig","id":1}"#;
        let response = service.ready().await.unwrap().call(request(body, None)).await.unwrap();

        assert_auth_rejection(&response);
    }

    #[tokio::test]
    async fn test_app_check_layer_rejects_missing_token() {
        let server = Server::new_async().await;
        let mut service = test_service(&server);

        let response = service.ready().await.unwrap().call(request(SIGN_BODY, None)).await.unwrap();

        assert_auth_rejection(&response);
    }

    #[tokio::test]
    async fn test_app_check_layer_rejects_empty_token() {
        let server = Server::new_async().await;
        let mut service = test_service(&server);

        let response =
            service.ready().await.unwrap().call(request(SIGN_BODY, Some(""))).await.unwrap();

        assert_auth_rejection(&response);
    }

    #[tokio::test]
    async fn test_app_check_layer_rejects_invalid_token() {
        let mut server = Server::new_async().await;
        let _jwks = jwks_mock(&mut server).create_async().await;
        let mut service = test_service(&server);

        let expired = AppCheckTokenBuilder::new().expires_in(-3600).build();
        for token in ["not-a-jwt", expired.as_str()] {
            let response =
                service.ready().await.unwrap().call(request(SIGN_BODY, Some(token))).await.unwrap();
            assert_auth_rejection(&response);
        }
    }

    #[tokio::test]
    async fn test_app_check_layer_rejects_when_key_set_is_unavailable() {
        let mut server = Server::new_async().await;
        let _unavailable = server.mock("GET", "/v1/jwks").with_status(503).create_async().await;
        let mut service = test_service(&server);

        let token = AppCheckTokenBuilder::new().build();
        let response =
            service.ready().await.unwrap().call(request(SIGN_BODY, Some(&token))).await.unwrap();

        assert_auth_rejection(&response);
    }

    #[tokio::test]
    async fn test_app_check_layer_liveness_bypass() {
        let server = Server::new_async().await;
        let mut service = test_service(&server);

        let body = r#"{"jsonrpc":"2.0","method":"liveness","params":[],"id":1}"#;
        let response = service.ready().await.unwrap().call(request(body, None)).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}

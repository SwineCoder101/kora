use super::ConfigValidator;
use crate::{
    config::{classify_cors_origins, Config, CorsOriginsClassification},
    constant::{APP_CHECK_JWKS_URL, MAX_RECAPTCHA_SCORE, MIN_RECAPTCHA_SCORE},
    plugin::TransactionPluginRunner,
    validator::cache_validator::CacheValidator,
};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use url::Url;

const MIN_SIGN_TIMEOUT_SECONDS: u64 = 1;
const HIGH_SIGN_MAX_RETRIES_WARNING_THRESHOLD: u32 = 10;

impl ConfigValidator {
    pub(super) fn check_server(
        config: &Config,
        errors: &mut Vec<String>,
        warnings: &mut Vec<String>,
    ) {
        if config.kora.rate_limit == 0 {
            warnings.push("Rate limit is set to 0 - this will block all requests".to_string());
        }

        if config.metrics.enabled
            && config.metrics.fee_payer_balance.enabled
            && config.metrics.fee_payer_balance.expiry_seconds == 0
        {
            errors.push(
                "metrics.fee_payer_balance.expiry_seconds must be at least 1 second when fee payer balance metrics are enabled"
                    .to_string(),
            );
        }

        // Validate CORS origins
        match classify_cors_origins(&config.kora.cors_allow_origins) {
            CorsOriginsClassification::Empty => {
                warnings.push(
                    "cors_allow_origins is empty - all cross-origin requests will be blocked"
                        .to_string(),
                );
            }
            CorsOriginsClassification::Wildcard { has_redundant } => {
                if has_redundant {
                    warnings.push("cors_allow_origins contains '*' alongside specific origin(s). The specific origin(s) are redundant and will be silently ignored.".to_string());
                }
            }
            CorsOriginsClassification::AllInvalid => {
                warnings.push("cors_allow_origins contains no valid origin(s) (must be e.g., 'https://your-app.com') - all cross-origin requests will be blocked".to_string());
            }
            CorsOriginsClassification::ValidWithSomeInvalid { invalid_origins, .. } => {
                warnings.push(format!("cors_allow_origins contains {} invalid origin(s) that will be silently filtered out at runtime", invalid_origins.len()));
            }
            CorsOriginsClassification::AllValid { .. } => {}
        }

        if let Some(payment_address) = &config.kora.payment_address {
            if let Err(e) = Pubkey::from_str(payment_address) {
                errors.push(format!("Invalid payment address: {e}"));
            }
        }

        let score_threshold = config.kora.auth.recaptcha_score_threshold;
        if !(MIN_RECAPTCHA_SCORE..=MAX_RECAPTCHA_SCORE).contains(&score_threshold) {
            errors.push(format!(
                "recaptcha_score_threshold must be between {MIN_RECAPTCHA_SCORE} and {MAX_RECAPTCHA_SCORE}, got: {score_threshold}"
            ));
        }

        let methods = &config.kora.enabled_methods;
        if !methods.iter().any(|enabled| enabled) {
            warnings.push(
                "All rpc methods are disabled - this will block all functionality".to_string(),
            );
        }

        if config.kora.sign_timeout_seconds < MIN_SIGN_TIMEOUT_SECONDS {
            errors.push("sign_timeout_seconds must be at least 1 second".to_string());
        }
        if config.kora.sign_max_retries > HIGH_SIGN_MAX_RETRIES_WARNING_THRESHOLD {
            warnings.push(format!(
                "sign_max_retries ({}) is very high - consider reducing to prevent long request hangs",
                config.kora.sign_max_retries
            ));
        }

        let mut unique_plugins = std::collections::HashSet::new();
        for plugin in &config.kora.plugins.enabled {
            if !unique_plugins.insert(plugin.clone()) {
                warnings.push(format!("Duplicate transaction plugin configured: {:?}", plugin));
            }
        }

        let (plugin_errors, plugin_warnings) = TransactionPluginRunner::validate_config(config);
        errors.extend(plugin_errors);
        warnings.extend(plugin_warnings);
    }

    pub(super) fn check_bundle(config: &Config, errors: &mut Vec<String>) {
        if config.kora.bundle.enabled && config.kora.bundle.jito.simulate_bundle_url.is_none() {
            errors.push(
                "Bundle support is enabled but jito.simulate_bundle_url is not set. \
                simulateBundle is a Jito-Solana RPC method and requires a compatible RPC URL \
                (e.g. a Jito-Solana node, Helius, or QuickNode with Jito add-on)."
                    .to_string(),
            );
        }
    }

    pub(super) fn check_auth(
        config: &Config,
        errors: &mut Vec<String>,
        warnings: &mut Vec<String>,
    ) {
        let has_auth = config.kora.auth.has_resolved_auth();
        if !has_auth {
            warnings.push(
                "⚠️  SECURITY: No authentication configured (no api_keys, hmac_secret or \
                app_check_project_number). \
                Authentication is strongly recommended for production deployments. \
                Consider enabling api_keys, hmac_secret or app_check_project_number in [kora.auth]."
                    .to_string(),
            );
        }

        // The running server resolves auth env-first, so a stale KORA_* environment variable
        // silently overrides a rotated kora.toml secret and keeps the retired credential valid.
        warnings.extend(config.kora.auth.env_overridden_fields());

        Self::check_app_check(config, errors, warnings);
    }

    fn check_app_check(config: &Config, errors: &mut Vec<String>, warnings: &mut Vec<String>) {
        let auth = &config.kora.auth;

        let Some(project_number) = auth.resolved_app_check_project_number() else {
            // Without a project number the layer is not installed at all, so these settings
            // would read as protection that is not there.
            if !auth.app_check_app_ids.is_empty() || auth.app_check_jwks_url.is_some() {
                errors.push(
                    "app_check_app_ids / app_check_jwks_url are set but app_check_project_number \
                    is not, so App Check would not be enforced. Set app_check_project_number in \
                    [kora.auth] or remove the other App Check settings."
                        .to_string(),
                );
            }
            return;
        };

        if !project_number.bytes().all(|b| b.is_ascii_digit()) {
            errors.push(
                "app_check_project_number must be the numeric Firebase project number \
                (Firebase console > Project settings > General), not the project ID."
                    .to_string(),
            );
        }

        if let Some(jwks_url) = &auth.app_check_jwks_url {
            match Url::parse(jwks_url) {
                Ok(url) if matches!(url.scheme(), "http" | "https") => warnings.push(format!(
                    "⚠️  SECURITY: app_check_jwks_url overrides the Firebase App Check key set \
                    ({APP_CHECK_JWKS_URL}). Whoever serves that URL can mint tokens this node \
                    accepts. Only override it in tests."
                )),
                _ => errors.push("app_check_jwks_url must be an http(s) URL".to_string()),
            }
        }
    }

    pub(super) async fn check_caches(
        config: &Config,
        errors: &mut Vec<String>,
        warnings: &mut Vec<String>,
    ) {
        let usage_config = &config.kora.usage_limit;
        if usage_config.enabled {
            if usage_config.rules.is_empty() {
                errors.push(
                    "usage_limit.enabled is true but no rules are configured; add at least one \
                     [[kora.usage_limit.rules]] or set enabled = false"
                        .to_string(),
                );
            }

            let (usage_errors, usage_warnings) = CacheValidator::validate(usage_config).await;
            errors.extend(usage_errors);
            warnings.extend(usage_warnings);
        }

        if config.kora.cache.enabled {
            let (cache_errors, cache_warnings) =
                CacheValidator::validate_rpc_cache(&config.kora.cache).await;
            errors.extend(cache_errors);
            warnings.extend(cache_warnings);
        }
    }
}

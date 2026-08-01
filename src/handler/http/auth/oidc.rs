// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Small, self-contained OpenID Connect integration for open-source builds.
//!
//! This deliberately does not reuse the private enterprise Dex or OpenFGA crates. It implements
//! authentication and fixed-organization admission only; open-source authorization semantics are
//! unchanged.

use std::{collections::HashMap, fs, time::Duration};

use axum::{
    body::Body,
    extract::Query,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use config::{
    get_config, ider,
    meta::user::{DBUser, UserOrg, UserRole},
    utils::{json, rand::generate_random_string},
};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use super::validator::{AuthError, AuthValidationResult, RequestData};
use crate::{
    common::{
        meta::user::AuthTokens,
        utils::auth::{V2_API_PREFIX, is_valid_email},
    },
    service::{db, organization, users},
};

const OIDC_BINDING_NAMESPACE: &str = "creator_signal_oidc_binding";
const OIDC_SESSION_PREFIX: &str = "oidc:";
const OIDC_STATE_SESSION_PREFIX: &str = "oidc-state:";
const FRONTEND_JWT_HEADER: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";

#[derive(Clone, Debug)]
struct EffectiveConfig {
    issuer: String,
    client_id: String,
    client_secret: String,
    token_endpoint_auth_method: String,
    redirect_url: String,
    post_login_url: String,
    scopes: String,
    default_org: String,
    role_claim: String,
    required_role: String,
    session_max_age: i64,
    state_ttl: i64,
    insecure_allow_http: bool,
}

#[derive(Debug, Deserialize)]
struct ProviderMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginState {
    verifier: String,
    nonce: String,
    created_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    #[serde(rename = "error_description")]
    _error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
}

#[derive(Clone, Debug)]
struct Identity {
    issuer: String,
    subject: String,
    email: String,
    name: String,
    given_name: String,
    family_name: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct SubjectBinding {
    issuer: String,
    subject: String,
    email: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OidcSession {
    version: u8,
    issuer: String,
    subject: String,
    email: String,
}

fn error_response(status: StatusCode, message: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "error": message }).to_string(),
        ))
        .unwrap()
}

fn public_url_is_allowed(raw: &str, allow_http: bool) -> anyhow::Result<()> {
    let url = Url::parse(raw)?;
    if url.scheme() != "https" && !(allow_http && url.scheme() == "http") {
        anyhow::bail!("OIDC URLs must use HTTPS");
    }
    if url.host_str().is_none() {
        anyhow::bail!("OIDC URL must include a host");
    }
    Ok(())
}

fn effective_config() -> anyhow::Result<EffectiveConfig> {
    let cfg = get_config();
    let oidc = &cfg.oidc;
    if !oidc.enabled {
        anyhow::bail!("OIDC is disabled");
    }

    let issuer = oidc.issuer.trim().to_string();
    if issuer.is_empty() || oidc.client_id.trim().is_empty() || oidc.redirect_url.trim().is_empty()
    {
        anyhow::bail!("OIDC issuer, client ID, and redirect URL are required");
    }
    if !oidc.client_secret.is_empty() && !oidc.client_secret_file.is_empty() {
        anyhow::bail!("set only one of ZO_OIDC_CLIENT_SECRET or ZO_OIDC_CLIENT_SECRET_FILE");
    }

    let client_secret = if !oidc.client_secret_file.is_empty() {
        fs::read_to_string(&oidc.client_secret_file)
            .map_err(|e| anyhow::anyhow!("failed to read OIDC client secret file: {e}"))?
            .trim()
            .to_string()
    } else {
        oidc.client_secret.trim().to_string()
    };
    if client_secret.is_empty() {
        anyhow::bail!("OIDC client secret is required");
    }
    if oidc.default_org.trim().is_empty() {
        anyhow::bail!("OIDC default organization is required");
    }
    if oidc.required_role.trim().is_empty() || oidc.role_claim.trim().is_empty() {
        anyhow::bail!("OIDC role claim and required role must be configured");
    }
    if !oidc
        .scopes
        .split_ascii_whitespace()
        .any(|scope| scope == "openid")
    {
        anyhow::bail!("OIDC scopes must include openid");
    }
    if !(60..=86_400).contains(&oidc.session_max_age) || !(60..=900).contains(&oidc.state_ttl) {
        anyhow::bail!("OIDC session/state lifetime is outside the allowed range");
    }
    let token_endpoint_auth_method = oidc.token_endpoint_auth_method.trim();
    if !matches!(
        token_endpoint_auth_method,
        "client_secret_basic" | "client_secret_post"
    ) {
        anyhow::bail!("unsupported OIDC token endpoint authentication method");
    }
    if !oidc.insecure_allow_http && !cfg.auth.cookie_secure_only {
        anyhow::bail!("ZO_COOKIE_SECURE_ONLY must be true for production OIDC");
    }

    public_url_is_allowed(&issuer, oidc.insecure_allow_http)?;
    public_url_is_allowed(&oidc.redirect_url, oidc.insecure_allow_http)?;

    let post_login_url = if oidc.post_login_url.is_empty() {
        format!(
            "{}{}{}",
            cfg.common.web_url.trim_end_matches('/'),
            cfg.common.base_uri,
            "/web/cb"
        )
    } else {
        oidc.post_login_url.clone()
    };
    public_url_is_allowed(&post_login_url, oidc.insecure_allow_http)?;

    Ok(EffectiveConfig {
        issuer,
        client_id: oidc.client_id.trim().to_string(),
        client_secret,
        token_endpoint_auth_method: token_endpoint_auth_method.to_string(),
        redirect_url: oidc.redirect_url.trim().to_string(),
        post_login_url,
        scopes: oidc.scopes.trim().to_string(),
        default_org: oidc.default_org.trim().replace(' ', "_"),
        role_claim: oidc.role_claim.trim().to_string(),
        required_role: oidc.required_role.trim().to_string(),
        session_max_age: oidc.session_max_age,
        state_ttl: oidc.state_ttl,
        insecure_allow_http: oidc.insecure_allow_http,
    })
}

fn http_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?)
}

async fn discover(cfg: &EffectiveConfig) -> anyhow::Result<ProviderMetadata> {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        cfg.issuer.trim_end_matches('/')
    );
    let metadata = http_client()?
        .get(discovery_url)
        .send()
        .await?
        .error_for_status()?
        .json::<ProviderMetadata>()
        .await?;

    if metadata.issuer != cfg.issuer {
        anyhow::bail!("OIDC discovery issuer does not match configured issuer");
    }
    if !metadata.token_endpoint_auth_methods_supported.is_empty()
        && !metadata
            .token_endpoint_auth_methods_supported
            .contains(&cfg.token_endpoint_auth_method)
    {
        anyhow::bail!("configured token endpoint authentication method is not advertised");
    }
    for endpoint in [
        &metadata.authorization_endpoint,
        &metadata.token_endpoint,
        &metadata.jwks_uri,
    ] {
        public_url_is_allowed(endpoint, cfg.insecure_allow_http)?;
    }
    Ok(metadata)
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn state_session_id(state: &str) -> String {
    format!("oidc-state-{state}")
}

fn state_cookie(state: &str, max_age: i64) -> Cookie<'static> {
    let cfg = get_config();
    let mut cookie = Cookie::new("oidc_state", state.to_string());
    cookie.set_http_only(true);
    cookie.set_secure(cfg.auth.cookie_secure_only);
    cookie.set_path("/");
    cookie.set_same_site(SameSite::Lax);
    cookie.set_max_age(time::Duration::seconds(max_age));
    cookie
}

fn removed_state_cookie() -> Cookie<'static> {
    let mut cookie = state_cookie("", 0);
    cookie.set_expires(time::OffsetDateTime::UNIX_EPOCH);
    cookie
}

/// Starts an authorization-code flow with PKCE, nonce, and one-time state.
pub async fn login() -> Response {
    let cfg = match effective_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            log::error!("OIDC configuration error: {e}");
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "OIDC is unavailable");
        }
    };
    let metadata = match discover(&cfg).await {
        Ok(metadata) => metadata,
        Err(e) => {
            log::error!("OIDC discovery failed: {e}");
            return error_response(StatusCode::BAD_GATEWAY, "OIDC provider is unavailable");
        }
    };

    let verifier = generate_random_string(64);
    let state = generate_random_string(48);
    let nonce = generate_random_string(48);
    let login_state = LoginState {
        verifier: verifier.clone(),
        nonce,
        created_at: chrono::Utc::now().timestamp(),
    };
    let value = match json::to_string(&login_state) {
        Ok(value) => format!("{OIDC_STATE_SESSION_PREFIX}{value}"),
        Err(e) => {
            log::error!("Failed to serialize OIDC state: {e}");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "OIDC login failed");
        }
    };
    if let Err(e) = db::session::set_with_expiry(
        &state_session_id(&state),
        &value,
        login_state.created_at + cfg.state_ttl,
    )
    .await
    {
        log::error!("Failed to persist OIDC state: {e}");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "OIDC login failed");
    }

    let mut url = match Url::parse(&metadata.authorization_endpoint) {
        Ok(url) => url,
        Err(e) => {
            log::error!("Invalid OIDC authorization endpoint: {e}");
            return error_response(StatusCode::BAD_GATEWAY, "OIDC provider is unavailable");
        }
    };
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &cfg.client_id)
        .append_pair("redirect_uri", &cfg.redirect_url)
        .append_pair("scope", &cfg.scopes)
        .append_pair("state", &state)
        .append_pair("nonce", &login_state.nonce)
        .append_pair("code_challenge", &pkce_challenge(&verifier))
        .append_pair("code_challenge_method", "S256");

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::SET_COOKIE,
            state_cookie(&state, cfg.state_ttl).to_string(),
        )
        .body(Body::from(json::to_string(&url.to_string()).unwrap()))
        .unwrap()
}

async fn exchange_code(
    cfg: &EffectiveConfig,
    metadata: &ProviderMetadata,
    code: &str,
    verifier: &str,
) -> anyhow::Result<TokenResponse> {
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", cfg.redirect_url.as_str()),
        ("code_verifier", verifier),
    ];
    let client = http_client()?;
    let request = if cfg.token_endpoint_auth_method == "client_secret_basic" {
        client
            .post(&metadata.token_endpoint)
            .basic_auth(&cfg.client_id, Some(&cfg.client_secret))
            .form(&params)
    } else {
        let mut post_params = params.to_vec();
        post_params.push(("client_id", cfg.client_id.as_str()));
        post_params.push(("client_secret", cfg.client_secret.as_str()));
        client.post(&metadata.token_endpoint).form(&post_params)
    };
    Ok(request
        .send()
        .await?
        .error_for_status()?
        .json::<TokenResponse>()
        .await?)
}

fn claim_contains(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Array(values) => values.iter().any(|value| claim_contains(value, expected)),
        Value::Object(values) => {
            values.contains_key(expected)
                || values.values().any(|value| claim_contains(value, expected))
        }
        _ => false,
    }
}

async fn validate_id_token(
    cfg: &EffectiveConfig,
    metadata: &ProviderMetadata,
    token: &str,
    expected_nonce: &str,
) -> anyhow::Result<Identity> {
    let jwks = http_client()?
        .get(&metadata.jwks_uri)
        .send()
        .await?
        .error_for_status()?
        .json::<JwkSet>()
        .await?;
    let header = decode_header(token)?;
    if header.alg != Algorithm::RS256 {
        anyhow::bail!("OIDC ID token must use RS256");
    }
    let kid = header
        .kid
        .ok_or_else(|| anyhow::anyhow!("OIDC ID token is missing kid"))?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| anyhow::anyhow!("OIDC signing key was not found"))?;
    if jwk.common.key_algorithm.is_some() && jwk.common.key_algorithm != Some(KeyAlgorithm::RS256) {
        anyhow::bail!("OIDC signing key algorithm is not RS256");
    }
    let AlgorithmParameters::RSA(rsa) = &jwk.algorithm else {
        anyhow::bail!("OIDC signing key is not RSA");
    };
    let key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[cfg.client_id.as_str()]);
    validation.set_issuer(&[cfg.issuer.as_str()]);
    validation.set_required_spec_claims(&["aud", "exp", "iss", "sub"]);
    let claims = decode::<HashMap<String, Value>>(token, &key, &validation)?.claims;

    if claims.get("nonce").and_then(Value::as_str) != Some(expected_nonce) {
        anyhow::bail!("OIDC nonce validation failed");
    }
    let azp = claims.get("azp").and_then(Value::as_str);
    let multiple_audiences = claims
        .get("aud")
        .and_then(Value::as_array)
        .is_some_and(|audiences| audiences.len() > 1);
    if (multiple_audiences && azp.is_none()) || azp.is_some_and(|azp| azp != cfg.client_id) {
        anyhow::bail!("OIDC authorized party validation failed");
    }
    if claims.get("email_verified").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("OIDC email is not verified");
    }
    if !cfg.required_role.is_empty()
        && !claims
            .get(&cfg.role_claim)
            .is_some_and(|value| claim_contains(value, &cfg.required_role))
    {
        anyhow::bail!("OIDC required role is missing");
    }

    let email = claims
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    if !is_valid_email(&email) {
        anyhow::bail!("OIDC email claim is missing or invalid");
    }
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if subject.is_empty() {
        anyhow::bail!("OIDC subject claim is missing");
    }

    Ok(Identity {
        issuer: cfg.issuer.clone(),
        subject,
        email,
        name: claims
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        given_name: claims
            .get("given_name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        family_name: claims
            .get("family_name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

fn binding_key(kind: &str, value: &str) -> String {
    format!(
        "{kind}:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
    )
}

async fn read_binding(key: &str) -> anyhow::Result<Option<SubjectBinding>> {
    let keys = crate::service::kv::list(OIDC_BINDING_NAMESPACE, key).await?;
    if !keys.iter().any(|candidate| candidate == key) {
        return Ok(None);
    }
    let value = crate::service::kv::get(OIDC_BINDING_NAMESPACE, key).await?;
    Ok(Some(json::from_slice(&value)?))
}

async fn bind_subject(identity: &Identity) -> anyhow::Result<()> {
    let expected = SubjectBinding {
        issuer: identity.issuer.clone(),
        subject: identity.subject.clone(),
        email: identity.email.clone(),
    };
    let email_key = binding_key("email", &identity.email);
    let subject_key = binding_key(
        "subject",
        &format!("{}\n{}", identity.issuer, identity.subject),
    );
    for key in [&email_key, &subject_key] {
        if let Some(existing) = read_binding(key).await?
            && existing != expected
        {
            anyhow::bail!("OIDC identity is already bound to a different account");
        }
    }
    let value = Bytes::from(json::to_vec(&expected)?);
    crate::service::kv::set(OIDC_BINDING_NAMESPACE, &email_key, value.clone()).await?;
    crate::service::kv::set(OIDC_BINDING_NAMESPACE, &subject_key, value).await?;
    Ok(())
}

async fn provision_user(cfg: &EffectiveConfig, identity: &Identity) -> anyhow::Result<bool> {
    organization::check_and_create_org_without_ofga(&cfg.default_org).await?;
    if let Some(existing) = db::user::get_user_by_email(&identity.email).await {
        if !existing.is_external {
            anyhow::bail!("OIDC cannot link an existing native-login account");
        }
        if existing
            .organizations
            .iter()
            .any(|org| org.role.is_service_account())
        {
            anyhow::bail!("service accounts cannot use OIDC login");
        }
        if !existing
            .organizations
            .iter()
            .any(|org| org.name == cfg.default_org)
        {
            db::org_users::add(
                &cfg.default_org,
                &identity.email,
                UserRole::Admin,
                &generate_random_string(16),
                Some(format!("rum{}", generate_random_string(16))),
            )
            .await?;
        }
        return Ok(false);
    }

    let (first_name, last_name) =
        if identity.given_name.is_empty() && identity.family_name.is_empty() {
            (identity.name.clone(), String::new())
        } else {
            (identity.given_name.clone(), identity.family_name.clone())
        };
    users::create_new_user(DBUser {
        email: identity.email.clone(),
        first_name,
        last_name,
        password: String::new(),
        salt: String::new(),
        organizations: vec![UserOrg {
            name: cfg.default_org.clone(),
            org_name: cfg.default_org.clone(),
            token: String::new(),
            rum_token: None,
            role: UserRole::Admin,
        }],
        is_external: true,
        password_ext: None,
    })
    .await?;
    Ok(true)
}

fn auth_cookie(session_id: &str, max_age: i64) -> Cookie<'static> {
    let auth_tokens = AuthTokens {
        access_token: format!("session {session_id}"),
        refresh_token: String::new(),
    };
    let encoded = config::utils::base64::encode(&json::to_string(&auth_tokens).unwrap());
    let cfg = get_config();
    let mut cookie = Cookie::new("auth_tokens", encoded);
    cookie.set_http_only(true);
    cookie.set_secure(cfg.auth.cookie_secure_only);
    cookie.set_path("/");
    cookie.set_max_age(time::Duration::seconds(max_age));
    cookie.set_expires(time::OffsetDateTime::now_utc() + time::Duration::seconds(max_age));
    cookie.set_same_site(if cfg.auth.cookie_same_site_lax {
        SameSite::Lax
    } else {
        SameSite::None
    });
    cookie
}

fn frontend_token(identity: &Identity) -> String {
    let payload = serde_json::json!({
        "sub": identity.subject,
        "email": identity.email,
        "name": identity.name,
        "given_name": identity.given_name,
        "family_name": identity.family_name,
        "is_valid": true,
    });
    format!(
        "{FRONTEND_JWT_HEADER}.{}.",
        config::utils::base64::encode_url(&json::to_string(&payload).unwrap())
    )
}

/// Completes the code flow, admits the user, and creates an opaque server-side session.
pub async fn callback(cookies: CookieJar, Query(query): Query<CallbackQuery>) -> Response {
    if query.error.is_some() {
        log::warn!("OIDC provider denied an authorization request");
        return error_response(StatusCode::UNAUTHORIZED, "OIDC login was denied");
    }
    let (Some(code), Some(state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "OIDC callback is missing code or state",
        );
    };
    if cookies.get("oidc_state").map(Cookie::value) != Some(state) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "OIDC state is not bound to this browser",
        );
    }
    let cfg = match effective_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            log::error!("OIDC configuration error: {e}");
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "OIDC is unavailable");
        }
    };
    let state_id = state_session_id(state);
    let state_value = match db::session::get(&state_id).await {
        Ok(value) => value,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "OIDC state is invalid"),
    };
    // Consume the state before exchanging the code so replay attempts fail closed.
    let _ = db::session::delete(&state_id).await;
    let login_state: LoginState = match state_value
        .strip_prefix(OIDC_STATE_SESSION_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("invalid OIDC state namespace"))
        .and_then(|value| json::from_str(value).map_err(Into::into))
    {
        Ok(value) => value,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "OIDC state is invalid"),
    };
    let state_age = chrono::Utc::now().timestamp() - login_state.created_at;
    if state_age < 0 || state_age > cfg.state_ttl {
        return error_response(StatusCode::BAD_REQUEST, "OIDC state has expired");
    }

    let metadata = match discover(&cfg).await {
        Ok(metadata) => metadata,
        Err(e) => {
            log::error!("OIDC discovery failed: {e}");
            return error_response(StatusCode::BAD_GATEWAY, "OIDC provider is unavailable");
        }
    };
    let tokens = match exchange_code(&cfg, &metadata, code, &login_state.verifier).await {
        Ok(tokens) => tokens,
        Err(e) => {
            log::warn!("OIDC code exchange failed: {e}");
            return error_response(StatusCode::UNAUTHORIZED, "OIDC login failed");
        }
    };
    let identity =
        match validate_id_token(&cfg, &metadata, &tokens.id_token, &login_state.nonce).await {
            Ok(identity) => identity,
            Err(e) => {
                log::warn!("OIDC ID token validation failed: {e}");
                return error_response(StatusCode::UNAUTHORIZED, "OIDC identity was rejected");
            }
        };
    if let Err(e) = bind_subject(&identity).await {
        log::warn!("OIDC subject binding failed: {e}");
        return error_response(StatusCode::UNAUTHORIZED, "OIDC identity was rejected");
    }
    let new_user = match provision_user(&cfg, &identity).await {
        Ok(new_user) => new_user,
        Err(e) => {
            log::warn!("OIDC user admission failed: {e}");
            return error_response(StatusCode::FORBIDDEN, "OIDC user is not allowed");
        }
    };

    let session_id = ider::uuid();
    let session = OidcSession {
        version: 1,
        issuer: identity.issuer.clone(),
        subject: identity.subject.clone(),
        email: identity.email.clone(),
    };
    let session_value = format!(
        "{OIDC_SESSION_PREFIX}{}",
        json::to_string(&session).unwrap()
    );
    let expires_at = chrono::Utc::now().timestamp() + cfg.session_max_age;
    if let Err(e) = db::session::set_with_expiry(&session_id, &session_value, expires_at).await {
        log::error!("Failed to create OIDC session: {e}");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "OIDC login failed");
    }

    let separator = if cfg.post_login_url.contains('#') {
        "&"
    } else {
        "#"
    };
    let location = format!(
        "{}{separator}id_token={}&new_user_login={new_user}",
        cfg.post_login_url,
        frontend_token(&identity)
    );
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .header(
            header::SET_COOKIE,
            auth_cookie(&session_id, cfg.session_max_age).to_string(),
        )
        .header(header::SET_COOKIE, removed_state_cookie().to_string())
        .body(Body::empty())
        .unwrap()
}

fn session_id_from_cookie(cookies: &CookieJar) -> Option<String> {
    let cookie = cookies.get("auth_tokens")?;
    let decoded = config::utils::base64::decode_raw(cookie.value()).ok()?;
    let auth_tokens: AuthTokens = json::from_slice(&decoded).ok()?;
    auth_tokens
        .access_token
        .strip_prefix("session ")
        .map(ToOwned::to_owned)
}

fn parse_session(value: &str) -> anyhow::Result<OidcSession> {
    let value = value
        .strip_prefix(OIDC_SESSION_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("not an OIDC session"))?;
    let session: OidcSession = json::from_str(value)?;
    if session.version != 1 {
        anyhow::bail!("unsupported OIDC session version");
    }
    Ok(session)
}

/// Confirms that the current local session is still valid. Sessions are deliberately not extended
/// here; expiry requires a fresh authorization-code flow.
pub async fn refresh(cookies: CookieJar) -> Response {
    let Some(session_id) = session_id_from_cookie(&cookies) else {
        return error_response(StatusCode::UNAUTHORIZED, "OIDC session is missing");
    };
    match db::session::get(&session_id)
        .await
        .and_then(|value| parse_session(&value))
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => error_response(StatusCode::UNAUTHORIZED, "OIDC session has expired"),
    }
}

fn requested_org(req_data: &RequestData) -> Option<&str> {
    let cfg = get_config();
    let path = req_data
        .uri
        .path()
        .strip_prefix(&cfg.common.base_uri)
        .unwrap_or_else(|| req_data.uri.path())
        .strip_prefix("/api/")
        .unwrap_or_else(|| req_data.uri.path().trim_start_matches('/'));
    let columns = path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let candidate = if columns.first() == Some(&V2_API_PREFIX) {
        columns.get(1).copied()
    } else {
        columns.first().copied()
    }?;
    if matches!(
        candidate,
        "organizations" | "clusters" | "license" | "invites"
    ) {
        None
    } else {
        Some(candidate)
    }
}

/// Validates only opaque sessions created by this module. Provider access tokens are never
/// accepted as OpenObserve API credentials.
pub async fn token_validator(
    req_data: &RequestData,
    auth_info: &crate::common::utils::auth::AuthExtractor,
) -> Result<AuthValidationResult, AuthError> {
    let raw = auth_info
        .auth
        .strip_prefix("Bearer")
        .map(str::trim)
        .and_then(|value| value.strip_prefix("session "))
        .ok_or_else(|| AuthError::Unauthorized("Unsupported bearer token".to_string()))?;
    let stored = db::session::get(raw)
        .await
        .map_err(|_| AuthError::Unauthorized("OIDC session is invalid".to_string()))?;
    let session = parse_session(&stored)
        .map_err(|_| AuthError::Unauthorized("OIDC session is invalid".to_string()))?;
    let cfg = effective_config()
        .map_err(|_| AuthError::Unauthorized("OIDC is unavailable".to_string()))?;
    if session.issuer != cfg.issuer {
        return Err(AuthError::Unauthorized("OIDC issuer changed".to_string()));
    }

    let user = if let Some(org_id) = requested_org(req_data) {
        users::get_user(Some(org_id), &session.email).await
    } else {
        db::user::get_user_by_email(&session.email)
            .await
            .and_then(|user| user.get_all_users().into_iter().next())
    }
    .ok_or_else(|| AuthError::Unauthorized("OIDC user is not admitted".to_string()))?;

    Ok(AuthValidationResult {
        user_email: user.email,
        user_role: Some(user.role),
        is_internal_user: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_base64url_sha256() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn zitadel_role_object_is_supported() {
        let claim = serde_json::json!({
            "platform:operator": { "project-id": "project-id" },
            "other": { "project-id": "project-id" }
        });
        assert!(claim_contains(&claim, "platform:operator"));
        assert!(!claim_contains(&claim, "platform:admin"));
    }

    #[test]
    fn session_format_is_versioned_and_namespaced() {
        let session = OidcSession {
            version: 1,
            issuer: "https://auth.example.com".to_string(),
            subject: "123".to_string(),
            email: "operator@example.com".to_string(),
        };
        let encoded = format!(
            "{OIDC_SESSION_PREFIX}{}",
            serde_json::to_string(&session).unwrap()
        );
        assert_eq!(parse_session(&encoded).unwrap().email, session.email);
        assert!(parse_session("plain-token").is_err());
    }

    #[test]
    fn insecure_provider_urls_are_rejected_by_default() {
        assert!(public_url_is_allowed("http://auth.example.com", false).is_err());
        assert!(public_url_is_allowed("https://auth.example.com", false).is_ok());
        assert!(public_url_is_allowed("http://localhost:8080", true).is_ok());
    }
}

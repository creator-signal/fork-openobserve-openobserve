// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Narrow, file-backed automation identities for the Creator Signal OSS build.
//!
//! This is deliberately not a general-purpose RBAC implementation. It gives
//! three fixed machine principals only the ingestion, bounded aggregate-query,
//! or governed dashboard operations needed by deployment acceptance.

use std::path::Path;

use axum::http::Method;
use common::meta::user::TokenValidationResponse;
use config::{get_config, meta::user::UserRole};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::validator::AuthError;

pub const INGEST_IDENTITY: &str = "creator-signal-ingest";
pub const QUERY_IDENTITY: &str = "creator-signal-query";
pub const DASHBOARD_IDENTITY: &str = "creator-signal-dashboard-reconciler";
pub const POLICY_SCHEMA: &str = "creator-signal.openobserve-automation-policy/v1";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryTemplate {
    pub id: String,
    pub signal: String,
    pub sql: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DashboardDefinition {
    pub title: String,
    pub body_sha256: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationPolicy {
    pub schema: String,
    pub organization: String,
    pub max_time_range_micros: i64,
    pub max_result_size: u64,
    pub query_templates: Vec<QueryTemplate>,
    pub dashboards: Vec<DashboardDefinition>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Capability {
    Ingest,
    Query,
    Dashboard,
}

impl Capability {
    fn identity(self) -> &'static str {
        match self {
            Self::Ingest => INGEST_IDENTITY,
            Self::Query => QUERY_IDENTITY,
            Self::Dashboard => DASHBOARD_IDENTITY,
        }
    }

    fn role(self) -> UserRole {
        match self {
            Self::Ingest => UserRole::ServiceAccount,
            Self::Query => UserRole::Viewer,
            Self::Dashboard => UserRole::Editor,
        }
    }
}

fn capability(user_id: &str) -> Option<Capability> {
    match user_id {
        INGEST_IDENTITY => Some(Capability::Ingest),
        QUERY_IDENTITY => Some(Capability::Query),
        DASHBOARD_IDENTITY => Some(Capability::Dashboard),
        _ => None,
    }
}

fn valid_org(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn fixed_secret_path(path: &str) -> bool {
    let path = Path::new(path);
    path.is_absolute()
        && (path.starts_with("/run/secrets") || path.starts_with("/run/creator-signal-secrets"))
        && path.components().count() == 4
        && !path.to_string_lossy().contains("..")
}

fn fixed_policy_path(path: &str) -> bool {
    let path = Path::new(path);
    path.is_absolute()
        && (path.starts_with("/run/secrets")
            || path.starts_with("/run/creator-signal/repository-configs/openobserve"))
        && !path.to_string_lossy().contains("..")
}

fn secure_equal(left: &str, right: &str) -> bool {
    let left = Sha256::digest(left.as_bytes());
    let right = Sha256::digest(right.as_bytes());
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

async fn read_bounded_secret(path: &str) -> Result<String, AuthError> {
    if !fixed_secret_path(path) {
        return Err(AuthError::Forbidden(
            "Scoped automation credential path is invalid".to_string(),
        ));
    }
    let value = tokio::fs::read_to_string(path).await.map_err(|_| {
        AuthError::Forbidden("Scoped automation credential is unavailable".to_string())
    })?;
    let value = value.trim().to_string();
    if !(32..=256).contains(&value.len()) || value.chars().any(char::is_whitespace) {
        return Err(AuthError::Forbidden(
            "Scoped automation credential is invalid".to_string(),
        ));
    }
    Ok(value)
}

async fn configured_secrets() -> Result<[String; 3], AuthError> {
    let oidc = &get_config().oidc;
    let secrets = [
        read_bounded_secret(&oidc.automation_ingest_token_file).await?,
        read_bounded_secret(&oidc.automation_query_token_file).await?,
        read_bounded_secret(&oidc.automation_dashboard_token_file).await?,
    ];
    if secure_equal(&secrets[0], &secrets[1])
        || secure_equal(&secrets[0], &secrets[2])
        || secure_equal(&secrets[1], &secrets[2])
    {
        return Err(AuthError::Forbidden(
            "Scoped automation credentials must be distinct".to_string(),
        ));
    }
    Ok(secrets)
}

fn dashboard_path_allowed(path: &str, org: &str, method: &Method) -> bool {
    let base = format!("{org}/dashboards");
    if path == base {
        return method == Method::GET || method == Method::POST;
    }
    let Some(id) = path.strip_prefix(&format!("{base}/")) else {
        return false;
    };
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && (method == Method::GET || method == Method::PUT)
}

fn operation_allowed(capability: Capability, path: &str, method: &Method, org: &str) -> bool {
    if path.split('/').next() != Some(org) {
        return false;
    }
    match capability {
        Capability::Ingest => {
            *method == Method::POST
                && matches!(
                    path.strip_prefix(&format!("{org}/v1/")),
                    Some("logs" | "metrics" | "traces")
                )
        }
        Capability::Query => *method == Method::POST && path == format!("{org}/_search"),
        Capability::Dashboard => dashboard_path_allowed(path, org, method),
    }
}

/// Authenticate one of the three reserved automation usernames. `None` means
/// the username is not reserved and normal OpenObserve authentication should
/// continue. Reserved identities always fail closed and never fall back.
pub async fn validate_automation_credentials(
    user_id: &str,
    password: &str,
    path: &str,
    method: &Method,
) -> Option<Result<TokenValidationResponse, AuthError>> {
    let capability = capability(user_id)?;
    let oidc = &get_config().oidc;
    if !oidc.automation_enabled || !valid_org(oidc.automation_org.trim()) {
        return Some(Err(AuthError::Forbidden(
            "Scoped automation is unavailable".to_string(),
        )));
    }
    let org = oidc.automation_org.trim();
    let path = path.strip_prefix('/').unwrap_or(path);
    if !operation_allowed(capability, path, method, org) {
        return Some(Err(AuthError::Forbidden(
            "Scoped automation identity is not permitted for this operation".to_string(),
        )));
    }
    let secrets = match configured_secrets().await {
        Ok(secrets) => secrets,
        Err(error) => return Some(Err(error)),
    };
    let expected = match capability {
        Capability::Ingest => &secrets[0],
        Capability::Query => &secrets[1],
        Capability::Dashboard => &secrets[2],
    };
    if !secure_equal(expected, password) {
        return Some(Err(AuthError::Unauthorized(
            "Unauthorized Access".to_string(),
        )));
    }
    Some(Ok(TokenValidationResponse {
        is_valid: true,
        user_email: capability.identity().to_string(),
        is_internal_user: true,
        user_role: Some(capability.role()),
        user_name: capability.identity().to_string(),
        family_name: String::new(),
        given_name: capability.identity().to_string(),
    }))
}

pub async fn load_automation_policy() -> Result<AutomationPolicy, String> {
    let oidc = &get_config().oidc;
    let path = oidc.automation_policy_file.trim();
    if !fixed_policy_path(path) {
        return Err("Scoped automation policy path is invalid".to_string());
    }
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|_| "Scoped automation policy is unavailable".to_string())?;
    if bytes.is_empty() || bytes.len() > 128 * 1024 {
        return Err("Scoped automation policy size is invalid".to_string());
    }
    let policy: AutomationPolicy = serde_json::from_slice(&bytes)
        .map_err(|_| "Scoped automation policy is invalid".to_string())?;
    validate_policy(&policy, oidc.automation_org.trim())?;
    Ok(policy)
}

pub fn validate_policy(policy: &AutomationPolicy, configured_org: &str) -> Result<(), String> {
    if policy.schema != POLICY_SCHEMA {
        return Err("Scoped automation policy schema is unsupported".to_string());
    }
    if !valid_org(&policy.organization) || policy.organization != configured_org {
        return Err("Scoped automation policy organization does not match".to_string());
    }
    if !(1_000_000..=86_400_000_000).contains(&policy.max_time_range_micros)
        || !(1..=100).contains(&policy.max_result_size)
    {
        return Err("Scoped automation query bounds are invalid".to_string());
    }
    if policy.query_templates.is_empty() || policy.query_templates.len() > 64 {
        return Err("Scoped automation query template count is invalid".to_string());
    }
    let mut ids = std::collections::HashSet::new();
    for template in &policy.query_templates {
        if !ids.insert(&template.id)
            || template.id.is_empty()
            || template.id.len() > 64
            || !template
                .id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !matches!(template.signal.as_str(), "logs" | "metrics" | "traces")
            || template.sql.len() > 4096
            || !template.sql.starts_with("SELECT ")
            || !template.sql.contains("count(")
            || template.sql.contains(';')
            || template.sql.to_ascii_lowercase().contains("select *")
            || !placeholders_are_supported(&template.sql)
        {
            return Err("Scoped automation query template is unsafe".to_string());
        }
    }
    if policy.dashboards.is_empty()
        || policy.dashboards.len() > 64
        || policy.dashboards.iter().any(|dashboard| {
            !dashboard.title.starts_with("Creator Signal ")
                || dashboard.title.len() > 160
                || dashboard.title.contains(['\r', '\n'])
                || dashboard.body_sha256.len() != 64
                || !dashboard
                    .body_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
        })
        || policy
            .dashboards
            .iter()
            .map(|dashboard| &dashboard.title)
            .collect::<std::collections::HashSet<_>>()
            .len()
            != policy.dashboards.len()
    {
        return Err("Scoped automation dashboard title allowlist is invalid".to_string());
    }
    Ok(())
}

fn placeholders_are_supported(template: &str) -> bool {
    let mut remaining = template;
    while let Some(start) = remaining.find("{{") {
        let after = &remaining[start + 2..];
        let Some(end) = after.find("}}") else {
            return false;
        };
        if !matches!(&after[..end], "canary" | "release" | "environment") {
            return false;
        }
        remaining = &after[end + 2..];
    }
    !remaining.contains("}}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> AutomationPolicy {
        AutomationPolicy {
            schema: POLICY_SCHEMA.to_string(),
            organization: "default".to_string(),
            max_time_range_micros: 600_000_000,
            max_result_size: 10,
            query_templates: vec![QueryTemplate {
                id: "canary-count".to_string(),
                signal: "logs".to_string(),
                sql: "SELECT count(*) AS matches FROM \"default\" WHERE creator_signal_canary_id = '{{canary}}'".to_string(),
            }],
            dashboards: vec![DashboardDefinition {
                title: "Creator Signal 00 - Telemetry".to_string(),
                body_sha256: "a".repeat(64),
            }],
        }
    }

    #[test]
    fn policy_rejects_raw_or_unbounded_templates() {
        assert!(validate_policy(&policy(), "default").is_ok());
        let mut raw = policy();
        raw.query_templates[0].sql = "SELECT * FROM \"default\"".to_string();
        assert!(validate_policy(&raw, "default").is_err());
        let mut mismatched = policy();
        mismatched.organization = "other".to_string();
        assert!(validate_policy(&mismatched, "default").is_err());
    }

    #[test]
    fn fixed_capabilities_reject_cross_scope_paths() {
        assert!(operation_allowed(
            Capability::Query,
            "default/_search",
            &Method::POST,
            "default"
        ));
        assert!(!operation_allowed(
            Capability::Query,
            "default/_bulk",
            &Method::POST,
            "default"
        ));
        assert!(operation_allowed(
            Capability::Dashboard,
            "default/dashboards",
            &Method::POST,
            "default"
        ));
        assert!(!operation_allowed(
            Capability::Dashboard,
            "default/users",
            &Method::GET,
            "default"
        ));
        assert!(!operation_allowed(
            Capability::Dashboard,
            "default/_search",
            &Method::POST,
            "default"
        ));
        for (method, path) in [
            (Method::GET, "default/users"),
            (Method::GET, "default/roles"),
            (Method::GET, "default/tokens"),
            (Method::PUT, "default/settings"),
            (Method::POST, "default/v1/logs"),
            (Method::DELETE, "default/dashboards/governed"),
            (Method::POST, "other/dashboards"),
        ] {
            assert!(!operation_allowed(
                Capability::Dashboard,
                path,
                &method,
                "default"
            ));
        }
        assert!(!operation_allowed(
            Capability::Ingest,
            "default/_search",
            &Method::POST,
            "default"
        ));
        assert!(operation_allowed(
            Capability::Ingest,
            "default/v1/logs",
            &Method::POST,
            "default"
        ));
        assert!(!operation_allowed(
            Capability::Ingest,
            "default/_bulk",
            &Method::POST,
            "default"
        ));
    }
}

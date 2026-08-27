// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use axum::{
    body::{Body, Bytes, to_bytes},
    extract::Request,
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use openobserve_api_common::auth::automation::{
    AutomationPolicy, DASHBOARD_IDENTITY, QUERY_IDENTITY, QueryTemplate, load_automation_policy,
};
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};

const MAX_QUERY_BODY: usize = 64 * 1024;
const MAX_DASHBOARD_BODY: usize = 1024 * 1024;

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        "Scoped automation request is not permitted",
    )
        .into_response()
}

fn exact_object_keys(value: &Value, allowed: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object
            .keys()
            .all(|key| allowed.iter().any(|allowed| key == allowed))
    })
}

fn template_regex(template: &str) -> Result<Regex, ()> {
    let mut pattern = String::from("^");
    let mut remaining = template;
    while let Some(start) = remaining.find("{{") {
        pattern.push_str(&regex::escape(&remaining[..start]));
        let after = &remaining[start + 2..];
        let Some(end) = after.find("}}") else {
            return Err(());
        };
        pattern.push_str(match &after[..end] {
            "canary" => "[a-f0-9]{32}",
            "release" => "[a-f0-9]{40}",
            "environment" => "[a-z0-9][a-z0-9-]{0,31}",
            _ => return Err(()),
        });
        remaining = &after[end + 2..];
    }
    if remaining.contains("}}") {
        return Err(());
    }
    pattern.push_str(&regex::escape(remaining));
    pattern.push('$');
    Regex::new(&pattern).map_err(|_| ())
}

fn query_type(uri: &axum::http::Uri) -> Option<String> {
    let pairs = url::form_urlencoded::parse(uri.query()?.as_bytes()).collect::<Vec<_>>();
    if pairs.len() != 1 || pairs[0].0 != "type" {
        return None;
    }
    Some(pairs[0].1.to_string())
}

fn matching_template<'a>(
    policy: &'a AutomationPolicy,
    signal: &str,
    sql: &str,
) -> Option<&'a QueryTemplate> {
    policy.query_templates.iter().find(|template| {
        template.signal == signal
            && template_regex(&template.sql).is_ok_and(|pattern| pattern.is_match(sql))
    })
}

fn validate_query_request(
    uri: &axum::http::Uri,
    method: &Method,
    body: &[u8],
    policy: &AutomationPolicy,
) -> bool {
    if *method != Method::POST {
        return false;
    }
    let Some(signal) = query_type(uri) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    if !exact_object_keys(&value, &["query", "search_type", "timeout"])
        || value.get("search_type").and_then(Value::as_str) != Some("ui")
        || !value
            .get("timeout")
            .and_then(Value::as_u64)
            .is_some_and(|timeout| (1..=10).contains(&timeout))
    {
        return false;
    }
    let Some(query) = value.get("query") else {
        return false;
    };
    if !exact_object_keys(query, &["sql", "start_time", "end_time", "from", "size"])
        || query.get("from").and_then(Value::as_u64) != Some(0)
    {
        return false;
    }
    let Some(size) = query.get("size").and_then(Value::as_u64) else {
        return false;
    };
    let Some(start) = query.get("start_time").and_then(Value::as_i64) else {
        return false;
    };
    let Some(end) = query.get("end_time").and_then(Value::as_i64) else {
        return false;
    };
    let Some(sql) = query.get("sql").and_then(Value::as_str) else {
        return false;
    };
    size > 0
        && size <= policy.max_result_size
        && start > 0
        && end > start
        && end - start <= policy.max_time_range_micros
        && matching_template(policy, &signal, sql).is_some()
}

fn dashboard_query_allowed(uri: &axum::http::Uri, method: &Method) -> bool {
    let Some(raw) = uri.query() else {
        return true;
    };
    if *method != Method::PUT {
        return false;
    }
    url::form_urlencoded::parse(raw.as_bytes()).all(|(key, value)| match key.as_ref() {
        "folder" => value == "default",
        "hash" => {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        }
        _ => false,
    })
}

fn validate_dashboard_request(
    uri: &axum::http::Uri,
    method: &Method,
    body: &[u8],
    policy: &AutomationPolicy,
) -> bool {
    if !dashboard_query_allowed(uri, method) {
        return false;
    }
    if *method == Method::GET {
        return body.is_empty();
    }
    if method != Method::POST && method != Method::PUT {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    let Some(title) = value.get("title").and_then(Value::as_str) else {
        return false;
    };
    let digest = format!("{:x}", Sha256::digest(body));
    policy
        .dashboards
        .iter()
        .any(|dashboard| dashboard.title == title && dashboard.body_sha256 == digest)
}

fn governed_dashboard_title(value: &Value, policy: &AutomationPolicy) -> bool {
    let title = value
        .get("title")
        .or_else(|| value.get("v5").and_then(|dashboard| dashboard.get("title")))
        .and_then(Value::as_str);
    title.is_some_and(|title| {
        policy
            .dashboards
            .iter()
            .any(|dashboard| dashboard.title == title)
    })
}

fn filter_dashboard_value(
    mut value: Value,
    list: bool,
    policy: &AutomationPolicy,
) -> Option<Value> {
    if !list {
        return governed_dashboard_title(&value, policy).then_some(value);
    }
    let dashboards = value.get_mut("dashboards")?.as_array_mut()?;
    dashboards.retain(|dashboard| governed_dashboard_title(dashboard, policy));
    Some(value)
}

async fn filter_dashboard_response(
    response: Response,
    list: bool,
    policy: &AutomationPolicy,
) -> Response {
    if !response.status().is_success() {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(body) = to_bytes(body, MAX_DASHBOARD_BODY).await else {
        return forbidden();
    };
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return forbidden();
    };
    let Some(value) = filter_dashboard_value(value, list, policy) else {
        return forbidden();
    };
    let Ok(body) = serde_json::to_vec(&value) else {
        return forbidden();
    };
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(body))
}

async fn bounded_body(
    request: Request,
    limit: usize,
) -> Result<(axum::http::request::Parts, Bytes), Response> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, limit).await.map_err(|_| forbidden())?;
    Ok((parts, body))
}

pub async fn scoped_automation_middleware(request: Request, next: Next) -> Response {
    let identity = request
        .headers()
        .get("user_id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    if identity != QUERY_IDENTITY && identity != DASHBOARD_IDENTITY {
        return next.run(request).await;
    }
    let policy = match load_automation_policy().await {
        Ok(policy) => policy,
        Err(_) => return forbidden(),
    };
    let limit = if identity == QUERY_IDENTITY {
        MAX_QUERY_BODY
    } else {
        MAX_DASHBOARD_BODY
    };
    let (parts, body) = match bounded_body(request, limit).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let dashboard_get = identity == DASHBOARD_IDENTITY && parts.method == Method::GET;
    let dashboard_list = dashboard_get && parts.uri.path().ends_with("/dashboards");
    let allowed = if identity == QUERY_IDENTITY {
        validate_query_request(&parts.uri, &parts.method, &body, &policy)
    } else {
        validate_dashboard_request(&parts.uri, &parts.method, &body, &policy)
    };
    if !allowed {
        return forbidden();
    }
    let response = next.run(Request::from_parts(parts, Body::from(body))).await;
    if dashboard_get {
        filter_dashboard_response(response, dashboard_list, &policy).await
    } else {
        response
    }
}

#[cfg(test)]
mod tests {
    use openobserve_api_common::auth::automation::{
        AutomationPolicy, DashboardDefinition, POLICY_SCHEMA, QueryTemplate,
    };

    use super::*;

    fn policy(body: &[u8]) -> AutomationPolicy {
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
                body_sha256: format!("{:x}", Sha256::digest(body)),
            }],
        }
    }

    #[test]
    fn aggregate_query_is_exact_and_bounded() {
        let policy = policy(b"{}");
        let uri = "/api/default/_search?type=logs".parse().unwrap();
        let valid = serde_json::json!({
            "query": {
                "sql": format!("SELECT count(*) AS matches FROM \"default\" WHERE creator_signal_canary_id = '{}'", "a".repeat(32)),
                "start_time": 1_000_000,
                "end_time": 2_000_000,
                "from": 0,
                "size": 10
            },
            "search_type": "ui",
            "timeout": 5
        });
        assert!(validate_query_request(
            &uri,
            &Method::POST,
            &serde_json::to_vec(&valid).unwrap(),
            &policy
        ));
        let mut raw = valid.clone();
        raw["query"]["sql"] = Value::String("SELECT * FROM \"default\"".to_string());
        assert!(!validate_query_request(
            &uri,
            &Method::POST,
            &serde_json::to_vec(&raw).unwrap(),
            &policy
        ));
        let mut unbounded = valid;
        unbounded["query"]["end_time"] = Value::from(900_000_000_i64);
        assert!(!validate_query_request(
            &uri,
            &Method::POST,
            &serde_json::to_vec(&unbounded).unwrap(),
            &policy
        ));
    }

    #[test]
    fn dashboard_mutation_requires_an_exact_governed_body() {
        let body = br#"{"title":"Creator Signal 00 - Telemetry","version":5}"#;
        let policy = policy(body);
        let uri = "/api/default/dashboards".parse().unwrap();
        assert!(validate_dashboard_request(
            &uri,
            &Method::POST,
            body,
            &policy
        ));
        assert!(!validate_dashboard_request(
            &uri,
            &Method::POST,
            br#"{"title":"Creator Signal 00 - Telemetry","version":6}"#,
            &policy,
        ));
        assert!(!validate_dashboard_request(
            &uri,
            &Method::DELETE,
            &[],
            &policy
        ));
    }

    #[test]
    fn dashboard_reads_return_only_governed_definitions() {
        let body = br#"{"title":"Creator Signal 00 - Telemetry","version":5}"#;
        let policy = policy(body);
        let list = serde_json::json!({
            "dashboards": [
                { "title": "Creator Signal 00 - Telemetry", "dashboard_id": "governed" },
                { "title": "Unrelated operator dashboard", "dashboard_id": "unrelated" }
            ]
        });
        let filtered = filter_dashboard_value(list, true, &policy).unwrap();
        assert_eq!(filtered["dashboards"].as_array().unwrap().len(), 1);
        assert!(
            filter_dashboard_value(
                serde_json::json!({ "title": "Unrelated operator dashboard" }),
                false,
                &policy,
            )
            .is_none()
        );
        assert!(
            filter_dashboard_value(
                serde_json::json!({ "v5": { "title": "Creator Signal 00 - Telemetry" } }),
                false,
                &policy,
            )
            .is_some()
        );
    }
}

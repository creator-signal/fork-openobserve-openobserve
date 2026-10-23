use std::sync::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

struct Fixture {
    settings: Settings,
    state: Arc<Mutex<State>>,
    task: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}
struct State {
    generation: usize,
    denied: bool,
    partial: bool,
    oversized: bool,
    logins: usize,
    reads: usize,
    requests: usize,
    revokes: usize,
    slow_revoke: bool,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = tempfile::tempdir().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Fixture CA");
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let server_key = rcgen::KeyPair::generate().unwrap();
        let mut server_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        server_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Fixture server");
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();
        let client_key = rcgen::KeyPair::generate().unwrap();
        let mut client_params =
            rcgen::CertificateParams::new(vec!["client.fixture".into()]).unwrap();
        client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Fixture client");
        let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der());
        let server = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![server_cert.der().clone()], key.into())
            .unwrap();
        let ca_file = directory.path().join("ca.pem");
        let cert_file = directory.path().join("client.pem");
        let key_file = directory.path().join("client-key.pem");
        std::fs::write(&ca_file, ca.pem()).unwrap();
        std::fs::write(&cert_file, client_cert.pem()).unwrap();
        std::fs::write(&key_file, client_key.serialize_pem()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let settings = Settings {
            address: format!(
                "https://localhost:{}",
                listener.local_addr().unwrap().port()
            ),
            role: "fixture-role".into(),
            ca_file,
            cert_file,
            key_file,
            runtime_path: "kv/data/runtime".into(),
            oidc_path: "kv/data/oidc".into(),
            storage_path: "kv/data/storage".into(),
            refresh: Duration::from_secs(5),
            max_stale: Duration::from_secs(10),
        };
        let state = Arc::new(Mutex::new(State {
            generation: 1,
            denied: false,
            partial: false,
            oversized: false,
            logins: 0,
            reads: 0,
            requests: 0,
            revokes: 0,
            slow_revoke: false,
        }));
        let shared = state.clone();
        let task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let shared = shared.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(socket).await else {
                        return;
                    };
                    let mut input = Vec::new();
                    let mut buffer = [0; 4096];
                    loop {
                        let Ok(n) = stream.read(&mut buffer).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        input.extend_from_slice(&buffer[..n]);
                        if input.len() > 65536 {
                            return;
                        }
                        if let Some(header_end) = input.windows(4).position(|b| b == b"\r\n\r\n") {
                            let header =
                                String::from_utf8_lossy(&input[..header_end]).to_lowercase();
                            let length = header
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length: "))
                                .and_then(|n| n.parse::<usize>().ok())
                                .unwrap_or(0);
                            if input.len() >= header_end + 4 + length {
                                break;
                            }
                        }
                    }
                    let request = String::from_utf8_lossy(&input);
                    let route = request
                        .lines()
                        .next()
                        .unwrap_or("")
                        .split(' ')
                        .nth(1)
                        .unwrap_or("");
                    let (status, body) = {
                        let mut state = shared.lock().unwrap();
                        state.requests += 1;
                        let generation = state.generation;
                        if state.denied {
                            (403, "{\"errors\":[\"do-not-log-response-secret\"]}".into())
                        } else if route == "/v1/auth/token/revoke-self" {
                            state.revokes += 1;
                            (204, String::new())
                        } else if route == "/v1/auth/cert/login"
                            || route == "/v1/auth/token/renew-self"
                        {
                            let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
                            let valid = if route == "/v1/auth/cert/login" {
                                serde_json::from_str::<serde_json::Value>(body)
                                    .is_ok_and(|v| v["name"] == "fixture-role")
                            } else {
                                request
                                    .to_lowercase()
                                    .contains("x-vault-token: fixture-session-never-log")
                            };
                            if valid {
                                state.logins += 1;
                                (200, serde_json::json!({"auth":{"client_token":"fixture-session-never-log", "lease_duration":3600, "renewable":true}}).to_string())
                            } else {
                                (403, "{}".into())
                            }
                        } else if !request
                            .to_lowercase()
                            .contains("x-vault-token: fixture-session-never-log")
                        {
                            (403, "{}".into())
                        } else {
                            state.reads += 1;
                            if state.oversized {
                                (200, "x".repeat(MAX_BODY + 1))
                            } else if route == "/v1/kv/data/runtime" {
                                (200, serde_json::json!({"data":{"data":{
                                    "root_email":"fixture@example.test", "root_password":"fixture-root-password-never-log",
                                    "automation_ingest_token":format!("ingest-{generation:032}"),
                                    "automation_query_token":format!("query-{generation:032}"),
                                    "automation_dashboard_token":format!("dashboard-{generation:032}")}}}).to_string())
                            } else if route == "/v1/kv/data/oidc" {
                                if state.partial {
                                    (200, "{\"data\":{\"data\":{}}}".into())
                                } else {
                                    (200, serde_json::json!({"data":{"data":{"client_id":"fixture-client", "client_secret":format!("oidc-secret-{generation}")}}}).to_string())
                                }
                            } else if route == "/v1/kv/data/storage" {
                                (200, serde_json::json!({"data":{"data":{"access_key":"fixture-access", "secret_key":format!("storage-secret-{generation}")}}}).to_string())
                            } else {
                                (404, "{}".into())
                            }
                        }
                    };
                    let body = if route.starts_with("/v1/kv/data/") {
                        match serde_json::from_str::<serde_json::Value>(&body) {
                            Ok(mut value) if value["data"].is_object() => {
                                value["data"]["metadata"] = serde_json::json!({"version": shared.lock().unwrap().generation});
                                value.to_string()
                            }
                            _ => body,
                        }
                    } else {
                        body
                    };
                    let slow_revoke =
                        route == "/v1/auth/token/revoke-self" && shared.lock().unwrap().slow_revoke;
                    if slow_revoke {
                        tokio::time::sleep(Duration::from_secs(7)).await;
                    }
                    let response = format!(
                        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            settings,
            state,
            task,
            _directory: directory,
        }
    }
}

#[tokio::test]
async fn certificate_login_complete_snapshot_and_refresh_in_memory() {
    let fixture = Fixture::new().await;
    let provider = Provider::new(fixture.settings.clone()).unwrap();
    assert!(matches!(provider.current(), Err(Error::Unavailable)));
    provider.refresh().await.unwrap();
    let initial = provider.current().unwrap();
    assert_eq!(initial.get("client_secret").unwrap(), "oidc-secret-1");
    assert_eq!(fixture.state.lock().unwrap().reads, 3);
    fixture.state.lock().unwrap().generation = 2;
    provider.refresh().await.unwrap();
    let rotated = provider.current().unwrap();
    assert_eq!(rotated.get("client_secret").unwrap(), "oidc-secret-2");
    assert_eq!(rotated.get("secret_key").unwrap(), "storage-secret-2");
    assert_ne!(
        initial.get("automation_ingest_token").unwrap(),
        rotated.get("automation_ingest_token").unwrap()
    );
    assert_eq!(
        fixture.state.lock().unwrap().logins,
        1,
        "valid sessions are reused"
    );
    let debug = format!("{provider:?} {rotated:?}");
    assert!(!debug.contains("secret-2"));
    assert_eq!(
        std::fs::read_dir(fixture._directory.path())
            .unwrap()
            .count(),
        3,
        "only synthetic bootstrap files exist"
    );
}

#[tokio::test]
async fn incomplete_or_oversized_record_cannot_publish_partial_rotation() {
    let fixture = Fixture::new().await;
    let provider = Provider::new(fixture.settings.clone()).unwrap();
    provider.refresh().await.unwrap();
    {
        let mut state = fixture.state.lock().unwrap();
        state.generation = 2;
        state.partial = true;
    }
    assert_eq!(provider.refresh().await, Err(Error::Record));
    assert_eq!(
        provider.current().unwrap().get("client_secret").unwrap(),
        "oidc-secret-1"
    );
    {
        let mut state = fixture.state.lock().unwrap();
        state.partial = false;
        state.oversized = true;
    }
    assert_eq!(provider.refresh().await, Err(Error::Record));
    assert_eq!(
        provider.current().unwrap().get("secret_key").unwrap(),
        "storage-secret-1"
    );
}

#[tokio::test]
async fn outage_has_bounded_last_good_state_and_cold_start_fails_closed() {
    let fixture = Fixture::new().await;
    let provider = Provider::new(fixture.settings.clone()).unwrap();
    provider.refresh().await.unwrap();
    fixture.state.lock().unwrap().denied = true;
    let error = provider.refresh().await.unwrap_err();
    assert!(!format!("{error:?} {error}").contains("do-not-log-response-secret"));
    assert!(provider.current().is_ok());
    {
        let mut stored = provider.snapshot.write().unwrap();
        let snapshot = stored.as_ref().unwrap();
        *stored = Some(Arc::new(Snapshot {
            values: snapshot.values.clone(),
            obtained: Instant::now() - Duration::from_secs(11),
            versions: snapshot.versions,
        }));
    }
    assert!(matches!(provider.current(), Err(Error::Unavailable)));
    let cold = Provider::new(fixture.settings.clone()).unwrap();
    assert!(cold.refresh().await.is_err());
    assert!(cold.current().is_err());
    fixture.state.lock().unwrap().denied = false;
    provider.refresh().await.unwrap();
    assert!(provider.current().is_ok());
}

#[tokio::test]
async fn expired_session_renews_and_bootstrap_pair_is_reread() {
    let fixture = Fixture::new().await;
    let provider = Provider::new(fixture.settings.clone()).unwrap();
    provider.refresh().await.unwrap();
    {
        let session = provider.session.lock().await;
        let session = session.as_ref().unwrap();
        assert!(session.renew_at.duration_since(Instant::now()) > Duration::from_secs(2390));
        assert!(session.renew_at.duration_since(Instant::now()) <= Duration::from_secs(2400));
        assert!(session.expires > session.renew_at);
    }
    provider.session.lock().await.as_mut().unwrap().renew_at = Instant::now();
    provider.refresh().await.unwrap();
    assert_eq!(fixture.state.lock().unwrap().logins, 2);
    let key = std::fs::read(&fixture.settings.key_file).unwrap();
    std::fs::write(&fixture.settings.key_file, b"invalid-fixture-key").unwrap();
    assert_eq!(provider.refresh().await, Err(Error::Configuration));
    std::fs::write(&fixture.settings.key_file, key).unwrap();
    provider.refresh().await.unwrap();
}

#[tokio::test]
async fn consumer_signal_is_debounced_refreshes_without_restart_and_revokes_on_shutdown() {
    let fixture = Fixture::new().await;
    let provider = Arc::new(Provider::new(fixture.settings.clone()).unwrap());
    provider.refresh().await.unwrap();
    provider.start().await;
    fixture.state.lock().unwrap().generation = 2;
    assert!(provider.trigger_auth_refresh());
    assert!(!provider.trigger_auth_refresh());
    tokio::time::timeout(Duration::from_secs(3), async {
        while provider.current().unwrap().get("client_secret").unwrap() != "oidc-secret-2" {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(provider.lifecycle().auth_refreshes, 1);
    assert_eq!(provider.lifecycle().rotations, 1);
    assert!(provider.lifecycle().last_success > 0);
    let metrics = provider.metrics();
    assert!(metrics.contains("zo_openbao_snapshot_age_seconds"));
    assert!(metrics.contains("zo_openbao_ready 1"));
    assert!(!metrics.contains("oidc-secret"));
    assert!(!metrics.contains("fixture-session"));
    provider.shutdown().await.unwrap();
    assert_eq!(fixture.state.lock().unwrap().revokes, 1);
    assert!(provider.current().is_err());
    assert!(!provider.trigger_auth_refresh());
    assert!(provider.metrics().contains("zo_openbao_ready 0"));
    provider.shutdown().await.unwrap();
    assert_eq!(fixture.state.lock().unwrap().revokes, 1);
}

#[tokio::test]
async fn failures_back_off_cannot_be_bypassed_by_auth_signals_and_recover() {
    let fixture = Fixture::new().await;
    let provider = Arc::new(Provider::new(fixture.settings.clone()).unwrap());
    provider.refresh().await.unwrap();
    fixture.state.lock().unwrap().denied = true;
    assert!(provider.refresh().await.is_err());
    assert_eq!(provider.lifecycle().consecutive_failures, 1);
    assert_eq!(provider.lifecycle().refresh_failures, 1);
    assert!(!provider.trigger_auth_refresh());
    assert!(provider.delay().await > Duration::from_secs(4));
    provider.start().await;
    let requests = fixture.state.lock().unwrap().requests;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(fixture.state.lock().unwrap().requests, requests);
    fixture.state.lock().unwrap().denied = false;
    provider.refresh().await.unwrap();
    assert_eq!(provider.lifecycle().consecutive_failures, 0);
    assert_eq!(provider.lifecycle().refresh_failures, 1);
    assert!(provider.current().is_ok());
    provider.shutdown().await.unwrap();
    for failures in 1..100 {
        let delay = retry_delay(failures);
        assert!(delay >= Duration::from_secs(5));
        assert!(delay <= Duration::from_secs(300));
    }
}

#[tokio::test]
async fn wrong_ca_and_hostname_are_denied() {
    let fixture = Fixture::new().await;
    let mut settings = fixture.settings.clone();
    settings.address = settings.address.replace("localhost", "127.0.0.1");
    assert_eq!(
        Provider::new(settings).unwrap().refresh().await,
        Err(Error::Transport)
    );
    let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&fixture.settings.ca_file, other.cert.pem()).unwrap();
    assert_eq!(
        Provider::new(fixture.settings.clone())
            .unwrap()
            .refresh()
            .await,
        Err(Error::Transport)
    );
}

#[tokio::test]
async fn wrong_certificate_role_cannot_read_records() {
    let fixture = Fixture::new().await;
    let mut settings = fixture.settings.clone();
    settings.role = "wrong-role".into();
    let provider = Provider::new(settings).unwrap();
    assert_eq!(provider.refresh().await, Err(Error::Authentication));
    assert!(provider.current().is_err());
    assert_eq!(fixture.state.lock().unwrap().reads, 0);
}

#[tokio::test]
async fn configuration_rejects_redirectable_origins_and_path_escape() {
    let fixture = Fixture::new().await;
    for address in [
        "http://localhost",
        "https://user:password@localhost",
        "https://localhost/prefix",
        "https://localhost?token=bad",
        "https://localhost/#fragment",
    ] {
        let mut settings = fixture.settings.clone();
        settings.address = address.into();
        assert_eq!(settings.validate(), Err(Error::Configuration));
    }
    for path in [
        "kv/data/../sys",
        "kv/data/a%2fb",
        "kv/data/a?b",
        "/kv/data/a",
        "kv/metadata/a",
        "kv/data/*",
    ] {
        let mut settings = fixture.settings.clone();
        settings.runtime_path = path.into();
        assert_eq!(settings.validate(), Err(Error::Configuration));
    }
}

// Use separate processes: configuration tests must never race on global env.
#[test]
fn environment_sources_fail_closed() {
    for name in [
        "valid",
        "ZO_ROOT_USER_PASSWORD",
        "ZO_ROOT_USER_TOKEN",
        "ZO_S3_ACCESS_KEY",
        "ZO_S3_SECRET_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SHARED_CREDENTIALS_FILE",
        "ZO_OIDC_CLIENT_SECRET",
        "ZO_OIDC_CLIENT_SECRET_FILE",
        "ZO_OIDC_AUTOMATION_INGEST_TOKEN_FILE",
        "ZO_OIDC_AUTOMATION_QUERY_TOKEN_FILE",
        "ZO_OIDC_AUTOMATION_DASHBOARD_TOKEN_FILE",
        "ZO_S3_PROVIDER",
        "ZO_S3_ACCOUNTS",
        "ZO_OPENBAO_REFRESH_SECS",
        "ZO_OPENBAO_MAX_STALENESS_SECS",
    ] {
        let bootstrap = std::env::temp_dir().join("synthetic-bootstrap.pem");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .env_clear()
            .args(["--exact", "tests::environment_source_child", "--nocapture"])
            .env("OPENBAO_TEST_CASE", name)
            .env("ZO_OPENBAO_ENABLED", "true")
            .env("ZO_OPENBAO_ADDRESS", "https://fixture.example.test")
            .env("ZO_OPENBAO_CERT_ROLE", "fixture-role")
            .env("ZO_OPENBAO_CA_FILE", &bootstrap)
            .env("ZO_OPENBAO_CERT_FILE", &bootstrap)
            .env("ZO_OPENBAO_KEY_FILE", &bootstrap)
            .env("ZO_OPENBAO_RUNTIME_PATH", "kv/data/runtime")
            .env("ZO_OPENBAO_OIDC_PATH", "kv/data/oidc")
            .env("ZO_OPENBAO_STORAGE_PATH", "kv/data/storage");
        if name != "valid" {
            child.env(name, "synthetic-conflicting-source");
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "source validation failed for {name}"
        );
    }
}

#[test]
fn environment_source_child() {
    let Ok(case) = std::env::var("OPENBAO_TEST_CASE") else {
        return;
    };
    if case == "valid" {
        let settings = Settings::from_env().unwrap().unwrap();
        assert_eq!(settings.refresh, Duration::from_secs(60));
        assert_eq!(settings.max_stale, Duration::from_secs(300));
    } else {
        assert!(matches!(Settings::from_env(), Err(Error::Configuration)));
    }
}

#[tokio::test]
async fn shutdown_is_bounded_even_when_revoke_endpoint_hangs() {
    let fixture = Fixture::new().await;
    let provider = Arc::new(Provider::new(fixture.settings.clone()).unwrap());
    provider.refresh().await.unwrap();
    provider.start().await;
    fixture.state.lock().unwrap().slow_revoke = true;
    let started = Instant::now();
    assert_eq!(provider.shutdown().await, Err(Error::Transport));
    assert!(started.elapsed() < Duration::from_secs(6));
    assert!(provider.current().is_err());
    assert!(provider.session.lock().await.is_none());
}

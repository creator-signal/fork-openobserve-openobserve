// Certificate-authenticated KV v2 reads. Secrets and the session token live only
// in private process memory; errors intentionally carry no upstream payloads.
use std::{
    collections::BTreeMap,
    fmt,
    path::PathBuf,
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use reqwest::{Client, Method, StatusCode, header::HeaderValue};
use serde::Deserialize;

const MAX_BODY: usize = 65536;
static PROVIDER: OnceLock<Arc<Provider>> = OnceLock::new();
static MODE: OnceLock<bool> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Transport,
    Authentication,
    Record,
    Unavailable,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OpenBao {:?}", self)
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug)]
pub struct Settings {
    pub address: String,
    pub role: String,
    pub ca_file: PathBuf,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub runtime_path: String,
    pub oidc_path: String,
    pub storage_path: String,
    pub refresh: Duration,
    pub max_stale: Duration,
}
impl Settings {
    pub fn validate(&self) -> Result<(), Error> {
        let url = reqwest::Url::parse(&self.address).map_err(|_| Error::Configuration)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
            || self.role.is_empty()
            || !self
                .role
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || !(5..=300).contains(&self.refresh.as_secs())
            || self.max_stale < self.refresh
            || self.max_stale > Duration::from_secs(900)
        {
            return Err(Error::Configuration);
        }
        for path in [&self.runtime_path, &self.oidc_path, &self.storage_path] {
            if !path.contains("/data/")
                || path.starts_with('/')
                || path.ends_with('/')
                || path
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == "..")
                || !path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_-".contains(&b))
            {
                return Err(Error::Configuration);
            }
        }
        if [&self.ca_file, &self.cert_file, &self.key_file]
            .iter()
            .any(|p| !p.is_absolute())
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    pub fn from_env() -> Result<Option<Self>, Error> {
        match std::env::var("ZO_OPENBAO_ENABLED").as_deref() {
            Err(_) | Ok("false") => return Ok(None),
            Ok("true") => (),
            _ => return Err(Error::Configuration),
        }
        // API mode never silently falls back to exported credentials or files.
        for name in [
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
        ] {
            if std::env::var_os(name).is_some_and(|v| !v.is_empty()) {
                return Err(Error::Configuration);
            }
        }
        if std::env::var("ZO_S3_PROVIDER")
            .is_ok_and(|v| !matches!(v.as_str(), "" | "aws" | "s3" | "minio"))
            || std::env::var("ZO_S3_ACCOUNTS").is_ok_and(|v| !matches!(v.as_str(), "" | "default"))
        {
            return Err(Error::Configuration);
        }
        let get = |name| std::env::var(name).map_err(|_| Error::Configuration);
        let settings = Self {
            address: get("ZO_OPENBAO_ADDRESS")?,
            role: get("ZO_OPENBAO_CERT_ROLE")?,
            ca_file: get("ZO_OPENBAO_CA_FILE")?.into(),
            cert_file: get("ZO_OPENBAO_CERT_FILE")?.into(),
            key_file: get("ZO_OPENBAO_KEY_FILE")?.into(),
            runtime_path: get("ZO_OPENBAO_RUNTIME_PATH")?,
            oidc_path: get("ZO_OPENBAO_OIDC_PATH")?,
            storage_path: get("ZO_OPENBAO_STORAGE_PATH")?,
            refresh: env_duration("ZO_OPENBAO_REFRESH_SECS", 60)?,
            max_stale: env_duration("ZO_OPENBAO_MAX_STALENESS_SECS", 300)?,
        };
        settings.validate()?;
        Ok(Some(settings))
    }
}

fn env_duration(name: &str, default: u64) -> Result<Duration, Error> {
    let seconds = match std::env::var(name) {
        Ok(value) => value.parse().map_err(|_| Error::Configuration)?,
        Err(std::env::VarError::NotPresent) => default,
        Err(_) => return Err(Error::Configuration),
    };
    Ok(Duration::from_secs(seconds))
}

/// Non-secret lifecycle state. No role, path, credential or upstream payload.
#[derive(Clone, Default, Debug)]
pub struct Lifecycle {
    pub last_success: u64,
    pub consecutive_failures: u32,
    pub refresh_failures: u64,
    pub auth_refreshes: u64,
    pub rotations: u64,
    next_retry: Option<Instant>,
    last_trigger: Option<Instant>,
}

fn retry_delay(failures: u32) -> Duration {
    let ceiling = (10u64.saturating_mul(1u64 << failures.saturating_sub(1).min(5))).min(300);
    // Jitter is scheduling noise, never credential/key material.
    let noise = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    Duration::from_millis(ceiling * 500 + noise % (ceiling * 500 + 1))
}

pub struct Snapshot {
    values: BTreeMap<String, String>,
    obtained: Instant,
    versions: [u64; 3],
}
impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpenBaoSnapshot([REDACTED])")
    }
}
impl Snapshot {
    pub fn get(&self, key: &str) -> Result<String, Error> {
        self.values.get(key).cloned().ok_or(Error::Record)
    }
    fn assemble(runtime: Record, oidc: Record, storage: Record) -> Result<Self, Error> {
        let versions = [
            runtime.metadata.version,
            oidc.metadata.version,
            storage.metadata.version,
        ];
        if versions.contains(&0) {
            return Err(Error::Record);
        }
        let mut values = BTreeMap::new();
        for (record, keys) in [
            (
                runtime,
                &[
                    "root_email",
                    "root_password",
                    "automation_ingest_token",
                    "automation_query_token",
                    "automation_dashboard_token",
                ][..],
            ),
            (oidc, &["client_id", "client_secret"][..]),
            (storage, &["access_key", "secret_key"][..]),
        ] {
            for key in keys {
                let value = record
                    .data
                    .get(*key)
                    .and_then(|v| v.as_str())
                    .ok_or(Error::Record)?;
                if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
                    return Err(Error::Record);
                }
                values.insert((*key).to_string(), value.to_string());
            }
        }
        let tokens: Vec<_> = [
            "automation_ingest_token",
            "automation_query_token",
            "automation_dashboard_token",
        ]
        .iter()
        .map(|k| &values[*k])
        .collect();
        if tokens
            .iter()
            .any(|v| !(32..=256).contains(&v.len()) || v.chars().any(char::is_whitespace))
            || tokens[0] == tokens[1]
            || tokens[0] == tokens[2]
            || tokens[1] == tokens[2]
        {
            return Err(Error::Record);
        }
        Ok(Self {
            values,
            obtained: Instant::now(),
            versions,
        })
    }
}
#[derive(Deserialize)]
struct Record {
    data: BTreeMap<String, serde_json::Value>,
    metadata: Metadata,
}
#[derive(Deserialize)]
struct Metadata {
    version: u64,
}
#[derive(Deserialize)]
struct Kv {
    data: Record,
}
#[derive(Deserialize)]
struct Auth {
    client_token: String,
    lease_duration: u64,
    renewable: bool,
}
#[derive(Deserialize)]
struct Login {
    auth: Auth,
}
struct Session {
    token: HeaderValue,
    expires: Instant,
    renewable: bool,
    renew_at: Instant,
}
pub struct Provider {
    settings: Settings,
    session: tokio::sync::Mutex<Option<Session>>,
    snapshot: RwLock<Option<Arc<Snapshot>>>,
    lifecycle: RwLock<Lifecycle>,
    wake: tokio::sync::Notify,
    stopped: AtomicBool,
    worker: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpenBaoProvider([REDACTED])")
    }
}
impl Provider {
    pub fn new(settings: Settings) -> Result<Self, Error> {
        settings.validate()?;
        Ok(Self {
            settings,
            session: tokio::sync::Mutex::new(None),
            snapshot: RwLock::new(None),
            lifecycle: RwLock::new(Lifecycle::default()),
            wake: tokio::sync::Notify::new(),
            stopped: AtomicBool::new(false),
            worker: tokio::sync::Mutex::new(None),
        })
    }
    pub fn current(&self) -> Result<Arc<Snapshot>, Error> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        self.snapshot
            .read()
            .map_err(|_| Error::Unavailable)?
            .as_ref()
            .filter(|s| s.obtained.elapsed() < self.settings.max_stale)
            .cloned()
            .ok_or(Error::Unavailable)
    }
    async fn client(&self) -> Result<Client, Error> {
        // Re-read the existing certificate pair on each bounded refresh, so
        // atomic certificate renewal does not require process restart.
        let ca = tokio::fs::read(&self.settings.ca_file)
            .await
            .map_err(|_| Error::Configuration)?;
        let mut pem = tokio::fs::read(&self.settings.cert_file)
            .await
            .map_err(|_| Error::Configuration)?;
        pem.push(b'\n');
        pem.extend(
            tokio::fs::read(&self.settings.key_file)
                .await
                .map_err(|_| Error::Configuration)?,
        );
        let identity = reqwest::Identity::from_pem(&pem).map_err(|_| Error::Configuration)?;
        let ca = reqwest::Certificate::from_pem(&ca).map_err(|_| Error::Configuration)?;
        Client::builder()
            .identity(identity)
            .add_root_certificate(ca)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .no_proxy()
            .build()
            .map_err(|_| Error::Configuration)
    }
    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        client: &Client,
        method: Method,
        route: &str,
        token: Option<&HeaderValue>,
        body: Option<serde_json::Value>,
    ) -> Result<T, Error> {
        let mut request = client.request(
            method,
            format!("{}/v1/{route}", self.settings.address.trim_end_matches('/')),
        );
        if let Some(token) = token {
            request = request.header("X-Vault-Token", token.clone());
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request.send().await.map_err(|_| Error::Transport)?;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err(Error::Authentication);
        }
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|n| n > MAX_BODY as u64)
        {
            return Err(Error::Record);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Transport)? {
            if chunk.len() > MAX_BODY - bytes.len() {
                return Err(Error::Record);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(if bytes.is_empty() { b"null" } else { &bytes })
            .map_err(|_| Error::Record)
    }
    async fn authenticate(&self, client: &Client, old: Option<&Session>) -> Result<Session, Error> {
        let renewed = if let Some(old) = old.filter(|s| s.renewable && s.expires > Instant::now()) {
            self.request::<Login>(
                client,
                Method::POST,
                "auth/token/renew-self",
                Some(&old.token),
                Some(serde_json::json!({})),
            )
            .await
            .ok()
        } else {
            None
        };
        let login = match renewed {
            Some(login) => login,
            None => {
                self.request(
                    client,
                    Method::POST,
                    "auth/cert/login",
                    None,
                    Some(serde_json::json!({"name": self.settings.role})),
                )
                .await?
            }
        };
        if login.auth.lease_duration == 0
            || login.auth.lease_duration > 86400
            || login.auth.client_token.is_empty()
        {
            return Err(Error::Authentication);
        }
        let mut token =
            HeaderValue::from_str(&login.auth.client_token).map_err(|_| Error::Authentication)?;
        token.set_sensitive(true);
        Ok(Session {
            token,
            expires: Instant::now() + Duration::from_secs(login.auth.lease_duration.min(86400)),
            renewable: login.auth.renewable,
            renew_at: Instant::now() + Duration::from_secs(login.auth.lease_duration) * 2 / 3,
        })
    }
    async fn fetch(&self, client: &Client, token: &HeaderValue) -> Result<Snapshot, Error> {
        let runtime: Kv = self
            .request(
                client,
                Method::GET,
                &self.settings.runtime_path,
                Some(token),
                None,
            )
            .await?;
        let oidc: Kv = self
            .request(
                client,
                Method::GET,
                &self.settings.oidc_path,
                Some(token),
                None,
            )
            .await?;
        let storage: Kv = self
            .request(
                client,
                Method::GET,
                &self.settings.storage_path,
                Some(token),
                None,
            )
            .await?;
        Snapshot::assemble(runtime.data, oidc.data, storage.data)
    }
    async fn refresh_inner(&self) -> Result<(), Error> {
        let client = self.client().await?;
        let mut session = self.session.lock().await;
        if session
            .as_ref()
            .is_none_or(|s| s.renew_at <= Instant::now() || s.expires <= Instant::now())
        {
            *session = Some(self.authenticate(&client, session.as_ref()).await?);
        }
        let mut next = self
            .fetch(
                &client,
                &session.as_ref().ok_or(Error::Authentication)?.token,
            )
            .await;
        if matches!(next, Err(Error::Authentication)) {
            *session = None;
            *session = Some(self.authenticate(&client, None).await?);
            next = self
                .fetch(
                    &client,
                    &session.as_ref().ok_or(Error::Authentication)?.token,
                )
                .await;
        }
        // All three records must validate before publishing any changed value.
        let next = next?;
        let mut snapshot = self.snapshot.write().map_err(|_| Error::Unavailable)?;
        if snapshot
            .as_ref()
            .is_some_and(|old| old.versions != next.versions)
        {
            self.lifecycle
                .write()
                .map_err(|_| Error::Unavailable)?
                .rotations += 1;
        }
        *snapshot = Some(Arc::new(next));
        Ok(())
    }

    pub async fn refresh(&self) -> Result<(), Error> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        let result = self.refresh_inner().await;
        let mut state = self.lifecycle.write().map_err(|_| Error::Unavailable)?;
        if result.is_ok() {
            state.last_success = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            state.consecutive_failures = 0;
            state.next_retry = None;
        } else {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            state.refresh_failures = state.refresh_failures.saturating_add(1);
            state.next_retry = Some(Instant::now() + retry_delay(state.consecutive_failures));
        }
        result
    }

    /// Only schedules refresh; never retries the failed consumer operation.
    pub fn trigger_auth_refresh(&self) -> bool {
        if self.stopped.load(Ordering::Acquire) {
            return false;
        }
        let Ok(mut state) = self.lifecycle.write() else {
            return false;
        };
        let now = Instant::now();
        if state.next_retry.is_some_and(|at| at > now)
            || state
                .last_trigger
                .is_some_and(|at| now.duration_since(at) < Duration::from_secs(5))
        {
            return false;
        }
        state.last_trigger = Some(now);
        state.auth_refreshes = state.auth_refreshes.saturating_add(1);
        self.wake.notify_one();
        true
    }

    pub fn lifecycle(&self) -> Lifecycle {
        self.lifecycle
            .read()
            .map(|state| state.clone())
            .unwrap_or_default()
    }

    pub fn metrics(&self) -> String {
        let state = self.lifecycle();
        let age = self
            .snapshot
            .read()
            .ok()
            .and_then(|s| s.as_ref().map(|s| s.obtained.elapsed().as_secs_f64()))
            .unwrap_or(0.0);
        format!(
            "zo_openbao_last_success_timestamp_seconds {}\nzo_openbao_consecutive_failures {}\nzo_openbao_refresh_failures_total {}\nzo_openbao_auth_refreshes_total {}\nzo_openbao_rotations_total {}\nzo_openbao_snapshot_age_seconds {age}\nzo_openbao_ready {}\n",
            state.last_success,
            state.consecutive_failures,
            state.refresh_failures,
            state.auth_refreshes,
            state.rotations,
            u8::from(self.current().is_ok())
        )
    }

    async fn delay(&self) -> Duration {
        if let Some(at) = self.lifecycle().next_retry {
            return at.saturating_duration_since(Instant::now());
        }
        let session = self.session.lock().await;
        session
            .as_ref()
            .map(|s| {
                s.renew_at
                    .saturating_duration_since(Instant::now())
                    .min(self.settings.refresh)
            })
            .unwrap_or(self.settings.refresh)
    }

    pub async fn start(self: &Arc<Self>) {
        let mut worker = self.worker.lock().await;
        if worker.is_some() || self.stopped.load(Ordering::Acquire) {
            return;
        }
        let provider = self.clone();
        *worker = Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(provider.delay().await) => {},
                    _ = provider.wake.notified() => {},
                }
                if provider.stopped.load(Ordering::Acquire) {
                    break;
                }
                // A queued trigger cannot bypass an outage retry deadline.
                if provider
                    .lifecycle()
                    .next_retry
                    .is_some_and(|at| at > Instant::now())
                {
                    continue;
                }
                // refresh records every outcome in the exported lifecycle metrics.
                match provider.refresh().await {
                    Ok(()) | Err(_) => {}
                }
            }
        }));
    }

    pub async fn shutdown(&self) -> Result<(), Error> {
        if self.stopped.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        if let Some(worker) = self.worker.lock().await.take() {
            worker.abort();
            let _ = worker.await;
        }
        let revoke = async {
            let token = self.session.lock().await.take();
            if let Some(token) = token {
                let client = self.client().await?;
                self.request::<serde_json::Value>(
                    &client,
                    Method::POST,
                    "auth/token/revoke-self",
                    Some(&token.token),
                    Some(serde_json::json!({})),
                )
                .await?;
            }
            Ok(())
        };
        let result = tokio::time::timeout(Duration::from_secs(5), revoke)
            .await
            .unwrap_or(Err(Error::Transport));
        *self.snapshot.write().map_err(|_| Error::Unavailable)? = None;
        result
    }
}

pub fn enabled() -> bool {
    MODE.get()
        .copied()
        .unwrap_or_else(|| std::env::var("ZO_OPENBAO_ENABLED").as_deref() == Ok("true"))
}
pub fn validate_reload() -> Result<(), Error> {
    if MODE
        .get()
        .is_some_and(|mode| *mode != (std::env::var("ZO_OPENBAO_ENABLED").as_deref() == Ok("true")))
    {
        return Err(Error::Configuration);
    }
    if enabled() && Settings::from_env()?.is_none() {
        return Err(Error::Configuration);
    }
    Ok(())
}
pub fn current() -> Result<Arc<Snapshot>, Error> {
    PROVIDER.get().ok_or(Error::Unavailable)?.current()
}
pub fn ready() -> bool {
    !enabled() || current().is_ok()
}
pub fn trigger_auth_refresh() {
    if let Some(provider) = PROVIDER.get() {
        provider.trigger_auth_refresh();
    }
}
pub fn metrics() -> String {
    PROVIDER.get().map(|p| p.metrics()).unwrap_or_default()
}
pub async fn shutdown() -> Result<(), Error> {
    match PROVIDER.get() {
        Some(provider) => provider.shutdown().await,
        None => Ok(()),
    }
}
pub async fn initialize() -> Result<(), Error> {
    if PROVIDER.get().is_some() {
        return Ok(());
    }
    let settings = Settings::from_env()?;
    let _ = MODE.set(settings.is_some());
    let Some(settings) = settings else {
        return Ok(());
    };
    let provider = Arc::new(Provider::new(settings)?);
    if let Err(error) = provider.refresh().await {
        if let Err(cleanup) = provider.shutdown().await {
            eprintln!("OpenBao startup cleanup status={cleanup}");
        }
        return Err(error);
    }
    PROVIDER
        .set(provider.clone())
        .map_err(|_| Error::Configuration)?;
    provider.start().await;
    Ok(())
}

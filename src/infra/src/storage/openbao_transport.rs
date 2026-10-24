//! Observe S3 authentication failures without consuming, logging or replaying requests.
use async_trait::async_trait;
use http_body_util::BodyExt;
use object_store::client::{
    HttpClient, HttpConnector, HttpError, HttpRequest, HttpResponse, HttpResponseBody, HttpService,
    ReqwestConnector,
};

#[derive(Debug)]
pub struct AuthRefreshConnector;

impl HttpConnector for AuthRefreshConnector {
    fn connect(&self, options: &object_store::ClientOptions) -> object_store::Result<HttpClient> {
        Ok(HttpClient::new(AuthRefreshService {
            inner: ReqwestConnector::default().connect(options)?,
            trigger: config::openbao::trigger_auth_refresh,
        }))
    }
}

#[derive(Debug)]
struct AuthRefreshService {
    inner: HttpClient,
    trigger: fn(),
}

fn credential_error(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Some(code) = text
        .split_once("<Code>")
        .and_then(|(_, tail)| tail.split_once("</Code>"))
        .map(|(code, _)| code.trim())
    else {
        return false;
    };
    matches!(
        code,
        "InvalidAccessKeyId"
            | "SignatureDoesNotMatch"
            | "ExpiredToken"
            | "InvalidToken"
            | "TokenRefreshRequired"
    )
}

#[async_trait]
impl HttpService for AuthRefreshService {
    async fn call(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let response = self.inner.execute(request).await?;
        if response.status().as_u16() == 401 {
            (self.trigger)();
            return Ok(response);
        }
        if response.status().as_u16() != 403 {
            return Ok(response);
        }
        let (parts, body) = response.into_parts();
        let trigger = self.trigger;
        let mut prefix = Vec::new();
        let mut finished = false;
        let body = body.map_frame(move |frame| {
            if !finished && let Some(data) = frame.data_ref() {
                let take = data.len().min(65536 - prefix.len());
                prefix.extend_from_slice(&data[..take]);
                if credential_error(&prefix) {
                    trigger();
                    finished = true;
                } else if prefix.len() == 65536 {
                    finished = true;
                }
            }
            // Forward every original frame, including trailers, unchanged.
            frame
        });
        Ok(HttpResponse::from_parts(parts, HttpResponseBody::new(body)))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    static TRIGGERS: AtomicUsize = AtomicUsize::new(0);
    fn trigger() {
        TRIGGERS.fetch_add(1, Ordering::SeqCst);
    }
    #[derive(Debug)]
    struct Upstream {
        status: u16,
        body: &'static str,
        calls: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl HttpService for Upstream {
        async fn call(&self, _: HttpRequest) -> Result<HttpResponse, HttpError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut response = HttpResponse::new(self.body.to_string().into());
            *response.status_mut() = self.status.try_into().unwrap();
            Ok(response)
        }
    }
    #[tokio::test]
    async fn auth_errors_trigger_without_replay_or_response_changes() {
        for (status, body, expected) in [
            (403, "<Error><Code>InvalidAccessKeyId</Code></Error>", 1),
            (403, "<Error><Code>AccessDenied</Code></Error>", 0),
            (500, "upstream failure", 0),
            (401, "unauthorized", 1),
        ] {
            TRIGGERS.store(0, Ordering::SeqCst);
            let calls = Arc::new(AtomicUsize::new(0));
            let service = AuthRefreshService {
                inner: HttpClient::new(Upstream {
                    status,
                    body,
                    calls: calls.clone(),
                }),
                trigger,
            };
            let mut request = HttpRequest::new(object_store::client::HttpRequestBody::empty());
            *request.method_mut() = "POST".parse().unwrap();
            *request.uri_mut() = "https://s3.example.test/object".parse().unwrap();
            let response = service.call(request).await.unwrap();
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(
                response.into_body().bytes().await.unwrap().as_ref(),
                body.as_bytes()
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(TRIGGERS.load(Ordering::SeqCst), expected);
        }
    }
}

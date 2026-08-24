use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{
    ACCEPT, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HeaderMap, IF_MODIFIED_SINCE,
    IF_NONE_MATCH, LAST_MODIFIED, LOCATION,
};
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::RwLock;
use tokio::time::Instant;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const MIN_CACHE_TTL: Duration = Duration::from_secs(60);
const MAX_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const MAX_DOCUMENT_SIZE: usize = 5 * 1024;
const MAX_REDIRECTS: usize = 3;
const MAX_CACHE_ENTRIES: usize = 1000;

#[derive(Clone, Debug)]
pub struct ClientMetadataPolicy {
    pub allow_private_addresses: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientMetadata {
    pub redirect_uris: Vec<String>,
    pub client_name: String,
}

#[derive(Debug, Error)]
pub enum ClientMetadataError {
    #[error("invalid client metadata URL: {0}")]
    InvalidUrl(&'static str),
    #[error("client metadata target is blocked by network policy")]
    BlockedTarget,
    #[error("client metadata DNS lookup failed")]
    Dns,
    #[error("client metadata request failed")]
    Request,
    #[error("client metadata request timed out")]
    Timeout,
    #[error("client metadata returned HTTP {0}")]
    Http(StatusCode),
    #[error("client metadata redirect is invalid")]
    InvalidRedirect,
    #[error("client metadata exceeded the redirect limit")]
    TooManyRedirects,
    #[error("client metadata must use a JSON content type")]
    InvalidContentType,
    #[error("client metadata exceeds 5 KiB")]
    TooLarge,
    #[error("client metadata is invalid: {0}")]
    InvalidDocument(&'static str),
}

#[derive(Clone)]
struct CacheEntry {
    metadata: ClientMetadata,
    expires_at: Instant,
    etag: Option<String>,
    last_modified: Option<String>,
}

#[derive(Deserialize)]
struct MetadataDocument {
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    token_endpoint_auth_method: String,
}

struct FetchResult {
    metadata: Option<ClientMetadata>,
    headers: HeaderMap,
}

#[derive(Clone)]
pub struct ClientMetadataResolver {
    policy: ClientMetadataPolicy,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

impl ClientMetadataResolver {
    pub fn new(policy: ClientMetadataPolicy) -> Self {
        Self {
            policy,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn resolve(&self, client_id: &str) -> Result<ClientMetadata, ClientMetadataError> {
        let url = validate_client_id_url(client_id)?;
        let cached = self.cache.read().await.get(client_id).cloned();
        if let Some(entry) = &cached
            && entry.expires_at > Instant::now()
        {
            return Ok(entry.metadata.clone());
        }

        let result =
            tokio::time::timeout(TOTAL_TIMEOUT, self.fetch(&url, client_id, cached.as_ref()))
                .await
                .map_err(|_| ClientMetadataError::Timeout)??;

        let metadata = match result.metadata {
            Some(metadata) => metadata,
            None => cached
                .as_ref()
                .map(|entry| entry.metadata.clone())
                .ok_or(ClientMetadataError::Request)?,
        };

        match cache_lifetime(&result.headers) {
            Some(ttl) => {
                let entry = CacheEntry {
                    metadata: metadata.clone(),
                    expires_at: Instant::now() + ttl,
                    etag: header_string(&result.headers, ETAG)
                        .or_else(|| cached.as_ref().and_then(|entry| entry.etag.clone())),
                    last_modified: header_string(&result.headers, LAST_MODIFIED).or_else(|| {
                        cached
                            .as_ref()
                            .and_then(|entry| entry.last_modified.clone())
                    }),
                };
                let mut cache = self.cache.write().await;
                let now = Instant::now();
                cache.retain(|_, entry| entry.expires_at > now);
                if cache.len() >= MAX_CACHE_ENTRIES
                    && let Some(oldest) = cache
                        .iter()
                        .min_by_key(|(_, entry)| entry.expires_at)
                        .map(|(client_id, _)| client_id.clone())
                {
                    cache.remove(&oldest);
                }
                cache.insert(client_id.to_string(), entry);
            }
            None => {
                self.cache.write().await.remove(client_id);
            }
        }

        Ok(metadata)
    }

    async fn fetch(
        &self,
        initial_url: &Url,
        client_id: &str,
        cached: Option<&CacheEntry>,
    ) -> Result<FetchResult, ClientMetadataError> {
        let mut url = initial_url.clone();

        for redirects in 0..=MAX_REDIRECTS {
            let addresses = resolve_and_validate_target(&url, &self.policy).await?;
            let host = url
                .host_str()
                .ok_or(ClientMetadataError::InvalidUrl("host is required"))?;
            let client = reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .resolve_to_addrs(host, &addresses)
                .build()
                .map_err(|_| ClientMetadataError::Request)?;
            let mut request = client.get(url.clone()).header(ACCEPT, "application/json");
            if redirects == 0 {
                if let Some(etag) = cached.and_then(|entry| entry.etag.as_deref()) {
                    request = request.header(IF_NONE_MATCH, etag);
                }
                if let Some(last_modified) = cached.and_then(|entry| entry.last_modified.as_deref())
                {
                    request = request.header(IF_MODIFIED_SINCE, last_modified);
                }
            }

            let mut response = request
                .send()
                .await
                .map_err(|_| ClientMetadataError::Request)?;
            let status = response.status();
            if status == StatusCode::NOT_MODIFIED && redirects == 0 && cached.is_some() {
                return Ok(FetchResult {
                    metadata: None,
                    headers: response.headers().clone(),
                });
            }
            if status.is_redirection() {
                if redirects == MAX_REDIRECTS {
                    return Err(ClientMetadataError::TooManyRedirects);
                }
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or(ClientMetadataError::InvalidRedirect)?;
                url = url
                    .join(location)
                    .map_err(|_| ClientMetadataError::InvalidRedirect)?;
                continue;
            }
            if !status.is_success() {
                return Err(ClientMetadataError::Http(status));
            }
            validate_content_type(response.headers())?;
            if response
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<usize>().ok())
                .is_some_and(|length| length > MAX_DOCUMENT_SIZE)
            {
                return Err(ClientMetadataError::TooLarge);
            }

            let headers = response.headers().clone();
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| ClientMetadataError::Request)?
            {
                if body.len() + chunk.len() > MAX_DOCUMENT_SIZE {
                    return Err(ClientMetadataError::TooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            let document: MetadataDocument = serde_json::from_slice(&body)
                .map_err(|_| ClientMetadataError::InvalidDocument("document must be valid JSON"))?;
            let metadata = validate_document(document, client_id)?;
            return Ok(FetchResult {
                metadata: Some(metadata),
                headers,
            });
        }

        Err(ClientMetadataError::TooManyRedirects)
    }
}

fn validate_client_id_url(client_id: &str) -> Result<Url, ClientMetadataError> {
    let url = Url::parse(client_id)
        .map_err(|_| ClientMetadataError::InvalidUrl("not an absolute URL"))?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(ClientMetadataError::InvalidUrl("scheme must be HTTPS"));
    }
    if url.host_str().is_none() {
        return Err(ClientMetadataError::InvalidUrl("host is required"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ClientMetadataError::InvalidUrl(
            "user information is forbidden",
        ));
    }
    if url.fragment().is_some() {
        return Err(ClientMetadataError::InvalidUrl("fragments are forbidden"));
    }
    let path = client_id
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|index| &rest[index..]))
        .and_then(|path| path.split(['?', '#']).next())
        .ok_or(ClientMetadataError::InvalidUrl("path is required"))?;
    if path.split('/').any(|segment| matches!(segment, "." | "..")) {
        return Err(ClientMetadataError::InvalidUrl(
            "dot path segments are forbidden",
        ));
    }
    Ok(url)
}

async fn resolve_and_validate_target(
    url: &Url,
    policy: &ClientMetadataPolicy,
) -> Result<Vec<SocketAddr>, ClientMetadataError> {
    let host = url
        .host_str()
        .ok_or(ClientMetadataError::InvalidUrl("host is required"))?;
    let port = url
        .port_or_known_default()
        .ok_or(ClientMetadataError::InvalidUrl("port is required"))?;
    let addresses: Vec<_> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| ClientMetadataError::Dns)?
        .collect();
    if addresses.is_empty() {
        return Err(ClientMetadataError::Dns);
    }
    let all_private = addresses.iter().all(|address| !is_public_ip(address.ip()));
    if addresses.iter().any(|address| !is_public_ip(address.ip()))
        && !policy.allow_private_addresses
    {
        return Err(ClientMetadataError::BlockedTarget);
    }
    if url.scheme() != "https" && !(policy.allow_private_addresses && all_private) {
        return Err(ClientMetadataError::InvalidUrl("scheme must be HTTPS"));
    }
    Ok(addresses)
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return is_public_ipv4(ip);
            }
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || is_ipv6_prefix(ip, Ipv6Addr::UNSPECIFIED, 96)
                || is_ipv6_prefix(ip, Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96)
                || is_ipv6_prefix(ip, Ipv6Addr::new(0x0064, 0xff9b, 1, 0, 0, 0, 0, 0), 48)
                || is_ipv6_prefix(ip, Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64)
                || is_ipv6_prefix(ip, Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23)
                || is_ipv6_prefix(ip, Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16)
                || is_ipv6_prefix(ip, Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20)
                || is_ipv6_prefix(ip, Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16)
                || is_ipv6_prefix(ip, Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7)
                || is_ipv6_prefix(ip, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10)
                || is_ipv6_prefix(ip, Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10)
                || is_ipv6_prefix(ip, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32))
        }
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || in_ipv4_cidr(value, [0, 0, 0, 0], 8)
        || in_ipv4_cidr(value, [100, 64, 0, 0], 10)
        || in_ipv4_cidr(value, [192, 0, 0, 0], 24)
        || in_ipv4_cidr(value, [192, 0, 2, 0], 24)
        || in_ipv4_cidr(value, [192, 88, 99, 0], 24)
        || in_ipv4_cidr(value, [198, 18, 0, 0], 15)
        || in_ipv4_cidr(value, [198, 51, 100, 0], 24)
        || in_ipv4_cidr(value, [203, 0, 113, 0], 24)
        || value >= u32::from(Ipv4Addr::new(240, 0, 0, 0)))
}

fn in_ipv4_cidr(value: u32, network: [u8; 4], prefix: u32) -> bool {
    let mask = u32::MAX << (32 - prefix);
    value & mask == u32::from(Ipv4Addr::from(network)) & mask
}

fn is_ipv6_prefix(value: Ipv6Addr, network: Ipv6Addr, prefix: u32) -> bool {
    let mask = u128::MAX << (128 - prefix);
    u128::from(value) & mask == u128::from(network) & mask
}

fn is_loopback_redirect_uri(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "http"
            && url.host_str().is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            })
    })
}

fn validate_content_type(headers: &HeaderMap) -> Result<(), ClientMetadataError> {
    let media_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or_default();
    let media_type = media_type.to_ascii_lowercase();
    if media_type == "application/json"
        || (media_type.starts_with("application/") && media_type.ends_with("+json"))
    {
        Ok(())
    } else {
        Err(ClientMetadataError::InvalidContentType)
    }
}

fn validate_document(
    document: MetadataDocument,
    client_id: &str,
) -> Result<ClientMetadata, ClientMetadataError> {
    if document.client_id != client_id {
        return Err(ClientMetadataError::InvalidDocument(
            "client_id must exactly match the document URL",
        ));
    }
    if document.client_name.trim().is_empty() {
        return Err(ClientMetadataError::InvalidDocument(
            "client_name is required",
        ));
    }
    if document.redirect_uris.is_empty() {
        return Err(ClientMetadataError::InvalidDocument(
            "redirect_uris is required",
        ));
    }
    for redirect_uri in &document.redirect_uris {
        validate_redirect_uri(redirect_uri)?;
    }
    if !document
        .grant_types
        .iter()
        .any(|value| value == "authorization_code")
        || document
            .grant_types
            .iter()
            .any(|value| !matches!(value.as_str(), "authorization_code" | "refresh_token"))
    {
        return Err(ClientMetadataError::InvalidDocument(
            "grant_types must describe the authorization code public-client flow",
        ));
    }
    if !document.response_types.iter().any(|value| value == "code")
        || document.response_types.iter().any(|value| value != "code")
    {
        return Err(ClientMetadataError::InvalidDocument(
            "response_types must contain only code",
        ));
    }
    if document.token_endpoint_auth_method != "none" {
        return Err(ClientMetadataError::InvalidDocument(
            "token_endpoint_auth_method must be none",
        ));
    }

    Ok(ClientMetadata {
        redirect_uris: document.redirect_uris,
        client_name: document.client_name,
    })
}

fn validate_redirect_uri(redirect_uri: &str) -> Result<(), ClientMetadataError> {
    let url = Url::parse(redirect_uri)
        .map_err(|_| ClientMetadataError::InvalidDocument("redirect URI must be absolute"))?;
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err(ClientMetadataError::InvalidDocument(
            "redirect URI is invalid",
        ));
    }
    if url.scheme() == "https" {
        return Ok(());
    }
    if is_loopback_redirect_uri(redirect_uri) {
        Ok(())
    } else {
        Err(ClientMetadataError::InvalidDocument(
            "redirect URIs must use HTTPS or HTTP loopback",
        ))
    }
}

fn cache_lifetime(headers: &HeaderMap) -> Option<Duration> {
    let cache_control = header_string(headers, CACHE_CONTROL)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let directives: Vec<_> = cache_control.split(',').map(str::trim).collect();
    if directives.contains(&"no-store") {
        return None;
    }
    if directives.contains(&"no-cache") {
        return Some(Duration::ZERO);
    }
    directives
        .iter()
        .find_map(|directive| directive.strip_prefix("max-age="))
        .and_then(|value| value.trim_matches('"').parse::<u64>().ok())
        .map(Duration::from_secs)
        .map(|ttl| ttl.clamp(MIN_CACHE_TTL, MAX_CACHE_TTL))
        .or(Some(DEFAULT_CACHE_TTL))
}

fn header_string(headers: &HeaderMap, name: reqwest::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::http::{HeaderMap as AxumHeaderMap, HeaderValue};
    use axum::response::{IntoResponse, Redirect};
    use axum::routing::get;
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::*;

    fn development_resolver() -> ClientMetadataResolver {
        ClientMetadataResolver::new(ClientMetadataPolicy {
            allow_private_addresses: true,
        })
    }

    fn document(client_id: &str, redirect_uri: &str) -> serde_json::Value {
        json!({
            "client_id": client_id,
            "client_name": "Test MCP Client",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        })
    }

    async fn spawn_server(build: impl FnOnce(String) -> Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind metadata server");
        let base_url = format!(
            "http://{}",
            listener.local_addr().expect("metadata address")
        );
        let app = build(base_url.clone());
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve metadata server");
        });
        base_url
    }

    #[tokio::test]
    async fn resolves_valid_metadata_and_rejects_identity_and_redirect_mismatches() {
        let base_url = spawn_server(|base_url| {
            let valid_id = format!("{base_url}/valid.json");
            let valid_document = document(&valid_id, "http://127.0.0.1:3210/callback");
            let wrong_identity = document(
                "https://other.example/client.json",
                "http://127.0.0.1:3210/callback",
            );
            Router::new()
                .route(
                    "/valid.json",
                    get(move || async move {
                        (
                            [(CONTENT_TYPE.as_str(), "application/json")],
                            valid_document.to_string(),
                        )
                    }),
                )
                .route(
                    "/wrong.json",
                    get(move || async move {
                        (
                            [(CONTENT_TYPE.as_str(), "application/json")],
                            wrong_identity.to_string(),
                        )
                    }),
                )
        })
        .await;
        let resolver = development_resolver();

        let metadata = resolver
            .resolve(&format!("{base_url}/valid.json"))
            .await
            .expect("valid metadata");
        assert_eq!(metadata.client_name, "Test MCP Client");
        assert!(
            metadata
                .redirect_uris
                .contains(&"http://127.0.0.1:3210/callback".to_string())
        );
        assert!(
            !metadata
                .redirect_uris
                .contains(&"http://127.0.0.1:3211/callback".to_string())
        );

        let error = resolver
            .resolve(&format!("{base_url}/wrong.json"))
            .await
            .expect_err("identity mismatch must fail");
        assert!(matches!(error, ClientMetadataError::InvalidDocument(_)));
    }

    #[tokio::test]
    async fn follows_bounded_safe_redirects() {
        let base_url = spawn_server(|base_url| {
            let final_id = format!("{base_url}/redirect.json");
            let metadata = document(&final_id, "https://client.example/callback");
            Router::new()
                .route(
                    "/redirect.json",
                    get(|| async { Redirect::temporary("/middle") }),
                )
                .route(
                    "/middle",
                    get(|| async { Redirect::temporary("/document") }),
                )
                .route(
                    "/document",
                    get(move || async move {
                        (
                            [(CONTENT_TYPE.as_str(), "application/json")],
                            metadata.to_string(),
                        )
                    }),
                )
                .route("/loop", get(|| async { Redirect::temporary("/loop") }))
        })
        .await;
        let resolver = development_resolver();

        resolver
            .resolve(&format!("{base_url}/redirect.json"))
            .await
            .expect("safe redirect chain");
        let error = resolver
            .resolve(&format!("{base_url}/loop"))
            .await
            .expect_err("redirect loop must fail");
        assert!(matches!(error, ClientMetadataError::TooManyRedirects));
    }

    #[tokio::test]
    async fn caches_successes_and_conditionally_revalidates_no_cache_documents() {
        let cache_requests = Arc::new(AtomicUsize::new(0));
        let revalidation_requests = Arc::new(AtomicUsize::new(0));
        let saw_validator = Arc::new(AtomicUsize::new(0));
        let base_url = spawn_server({
            let cache_requests = cache_requests.clone();
            let revalidation_requests = revalidation_requests.clone();
            let saw_validator = saw_validator.clone();
            move |base_url| {
                let cached = document(
                    &format!("{base_url}/cached.json"),
                    "https://client.example/callback",
                );
                let revalidated = document(
                    &format!("{base_url}/revalidate.json"),
                    "https://client.example/callback",
                );
                Router::new()
                    .route(
                        "/cached.json",
                        get(move || {
                            let cache_requests = cache_requests.clone();
                            let cached = cached.clone();
                            async move {
                                cache_requests.fetch_add(1, Ordering::SeqCst);
                                (
                                    [
                                        (CONTENT_TYPE.as_str(), "application/json"),
                                        (CACHE_CONTROL.as_str(), "max-age=600"),
                                    ],
                                    cached.to_string(),
                                )
                            }
                        }),
                    )
                    .route(
                        "/revalidate.json",
                        get(move |headers: AxumHeaderMap| {
                            let revalidation_requests = revalidation_requests.clone();
                            let saw_validator = saw_validator.clone();
                            let revalidated = revalidated.clone();
                            async move {
                                revalidation_requests.fetch_add(1, Ordering::SeqCst);
                                if headers
                                    .get(IF_NONE_MATCH)
                                    .is_some_and(|value| value == "v1")
                                {
                                    saw_validator.fetch_add(1, Ordering::SeqCst);
                                    return (
                                        StatusCode::NOT_MODIFIED,
                                        [(CACHE_CONTROL.as_str(), "no-cache")],
                                        String::new(),
                                    )
                                        .into_response();
                                }
                                (
                                    StatusCode::OK,
                                    [
                                        (CONTENT_TYPE.as_str(), "application/json"),
                                        (CACHE_CONTROL.as_str(), "no-cache"),
                                        (ETAG.as_str(), "v1"),
                                    ],
                                    revalidated.to_string(),
                                )
                                    .into_response()
                            }
                        }),
                    )
            }
        })
        .await;
        let resolver = development_resolver();

        let cached_id = format!("{base_url}/cached.json");
        resolver
            .resolve(&cached_id)
            .await
            .expect("first cache fetch");
        resolver.resolve(&cached_id).await.expect("cached fetch");
        assert_eq!(cache_requests.load(Ordering::SeqCst), 1);

        let revalidate_id = format!("{base_url}/revalidate.json");
        resolver
            .resolve(&revalidate_id)
            .await
            .expect("initial fetch");
        resolver
            .resolve(&revalidate_id)
            .await
            .expect("conditional revalidation");
        assert_eq!(revalidation_requests.load(Ordering::SeqCst), 2);
        assert_eq!(saw_validator.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rejects_oversized_and_slow_documents() {
        let base_url = spawn_server(|base_url| {
            let slow = document(
                &format!("{base_url}/slow.json"),
                "https://client.example/callback",
            );
            Router::new()
                .route(
                    "/large.json",
                    get(|| async {
                        let mut headers = AxumHeaderMap::new();
                        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                        (headers, "x".repeat(MAX_DOCUMENT_SIZE + 1))
                    }),
                )
                .route(
                    "/slow.json",
                    get(move || {
                        let slow = slow.clone();
                        async move {
                            tokio::time::sleep(TOTAL_TIMEOUT + Duration::from_millis(100)).await;
                            (
                                [(CONTENT_TYPE.as_str(), "application/json")],
                                slow.to_string(),
                            )
                        }
                    }),
                )
        })
        .await;
        let resolver = development_resolver();

        assert!(matches!(
            resolver.resolve(&format!("{base_url}/large.json")).await,
            Err(ClientMetadataError::TooLarge)
        ));
        assert!(matches!(
            resolver.resolve(&format!("{base_url}/slow.json")).await,
            Err(ClientMetadataError::Timeout)
        ));
    }

    #[tokio::test]
    async fn blocks_private_and_unsafe_targets_in_production() {
        let resolver = ClientMetadataResolver::new(ClientMetadataPolicy {
            allow_private_addresses: false,
        });
        for client_id in [
            "http://127.0.0.1/client.json",
            "https://127.0.0.1/client.json",
            "https://169.254.169.254/latest/meta-data",
            "ftp://example.com/client.json",
        ] {
            assert!(
                resolver.resolve(client_id).await.is_err(),
                "accepted {client_id}"
            );
        }
    }

    #[test]
    fn classifies_special_purpose_addresses_as_non_public() {
        for address in [
            "0.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "198.18.0.1",
            "::1",
            "64:ff9b:1::1",
            "100::1",
            "2001:db8::1",
            "fc00::1",
            "fe80::1",
        ] {
            let address = address.parse::<IpAddr>().expect("test IP address");
            assert!(!is_public_ip(address), "classified {address} as public");
        }
        for address in ["8.8.8.8", "2606:4700:4700::1111"] {
            let address = address.parse::<IpAddr>().expect("test IP address");
            assert!(is_public_ip(address), "classified {address} as non-public");
        }
    }
}

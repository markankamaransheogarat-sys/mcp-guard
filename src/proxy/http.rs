use std::convert::Infallible;
use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use futures_util::StreamExt;
use tokio::net::TcpListener;

use crate::error::{GuardError, Result};
use crate::proxy::{ClientAction, GuardContext};

#[derive(Clone)]
struct HttpProxyState {
    ctx: GuardContext,
    upstream: String,
    client: reqwest::Client,
}

/// Start the SSE / Streamable HTTP MCP proxy server.
pub async fn run_http_proxy(ctx: GuardContext, bind: SocketAddr, upstream: String) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    let router = build_router(ctx, upstream);
    axum::serve(listener, router)
        .await
        .map_err(|e| GuardError::HttpProxy(e.to_string()))?;
    Ok(())
}

/// Build the Axum router (exposed for integration testing).
pub fn build_router(ctx: GuardContext, upstream: String) -> Router {
    let normalized = upstream.trim_end_matches('/').to_string();
    let state = HttpProxyState {
        ctx,
        upstream: normalized,
        client: reqwest::Client::new(),
    };
    Router::new()
        .route("/", any(handle_proxy))
        .route("/{*path}", any(handle_proxy))
        .with_state(state)
}

async fn handle_proxy(State(state): State<HttpProxyState>, req: Request) -> Response {
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let target_url = format!("{}{}", state.upstream, path_and_query);

    let req_headers = req.headers().clone();
    let body_bytes = match axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid body: {e}")).into_response();
        }
    };

    // Inspect JSON-RPC payload on POST/PUT requests
    let mut forward_body = body_bytes.to_vec();
    if method == Method::POST && !forward_body.is_empty() {
        if let Ok(text) = std::str::from_utf8(&forward_body) {
            match state.ctx.process_client_line(text) {
                ClientAction::Forward(fwd) => {
                    forward_body = fwd.into_bytes();
                }
                ClientAction::ImmediateReply(reply) => {
                    return (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/json")],
                        reply,
                    )
                        .into_response();
                }
            }
        }
    }

    let reqwest_method = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(e) => {
            return (StatusCode::METHOD_NOT_ALLOWED, e.to_string()).into_response();
        }
    };

    let mut builder = state.client.request(reqwest_method, &target_url);
    for (name, value) in &req_headers {
        if is_hop_by_hop(name) || name == header::HOST || name == header::CONTENT_LENGTH {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    if !forward_body.is_empty() {
        builder = builder.body(forward_body);
    }

    let upstream_resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("upstream request failed: {e}"),
            )
                .into_response();
        }
    };

    let status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut resp_headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers() {
        if is_hop_by_hop(name) || name == header::CONTENT_LENGTH {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            resp_headers.insert(n, v);
        }
    }

    let is_sse = upstream_resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("text/event-stream"));

    if is_sse {
        let ctx = state.ctx.clone();
        let stream = upstream_resp.bytes_stream().map(move |chunk| match chunk {
            Ok(bytes) => {
                let sanitized = sanitize_sse_chunk(&ctx, &bytes);
                Ok::<_, Infallible>(axum::body::Bytes::from(sanitized))
            }
            Err(_) => Ok::<_, Infallible>(axum::body::Bytes::new()),
        });
        let mut resp = Response::new(Body::from_stream(stream));
        *resp.status_mut() = status;
        *resp.headers_mut() = resp_headers;
        return resp;
    }

    let resp_bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("failed reading upstream response: {e}"),
            )
                .into_response();
        }
    };

    let out_bytes = if let Ok(text) = std::str::from_utf8(&resp_bytes) {
        if text.trim_start().starts_with('{') {
            state.ctx.process_server_line(text).into_bytes()
        } else {
            resp_bytes.to_vec()
        }
    } else {
        resp_bytes.to_vec()
    };

    let mut resp = Response::new(Body::from(out_bytes));
    *resp.status_mut() = status;
    *resp.headers_mut() = resp_headers;
    resp
}

fn sanitize_sse_chunk(ctx: &GuardContext, bytes: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return bytes.to_vec();
    };
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if let Some(payload) = line.strip_prefix("data:") {
            let trimmed = payload.trim();
            if trimmed.starts_with('{') {
                let sanitized = ctx.process_server_line(trimmed);
                out.push_str("data: ");
                out.push_str(&sanitized);
                if line.ends_with('\n') {
                    out.push('\n');
                }
                continue;
            }
        }
        out.push_str(line);
    }
    out.into_bytes()
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

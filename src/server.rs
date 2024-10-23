use crate::cache::Cache;
use anyhow::Result;
use bytes::Bytes;
use h3::server::Connection;
use h3::server::RequestStream;
use http::{Method, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tls_helpers::{certs_from_base64, privkey_from_base64, tls_acceptor_from_base64};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tracing::{error, info};

pub struct HyperStatic {
    fullchain_pem_base64: String,
    privkey_pem_base64: String,
    ssl_port: u16,
    cache: Arc<Cache>,
}

impl HyperStatic {
    pub fn new(
        fullchain_pem_base64: String,
        privkey_pem_base64: String,
        ssl_port: u16,
        public_folder: PathBuf,
    ) -> Self {
        let cache = Arc::new(Cache::new(public_folder));
        Self {
            fullchain_pem_base64,
            privkey_pem_base64,
            ssl_port,
            cache,
        }
    }

    pub async fn start(
        &self,
    ) -> Result<
        (
            oneshot::Receiver<()>,
            oneshot::Receiver<()>,
            watch::Sender<()>,
        ),
        Box<dyn Error + Send + Sync>,
    > {
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let (up_tx, up_rx) = oneshot::channel();
        let (fin_tx, fin_rx) = oneshot::channel();

        info!("Starting hyper-static server");

        {
            let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), self.ssl_port);
            let tls_acceptor = tls_acceptor_from_base64(
                &self.fullchain_pem_base64,
                &self.privkey_pem_base64,
                false,
                true,
            )?;

            let ssl_port = self.ssl_port;
            let srv_h2 = {
                let cache = Arc::clone(&self.cache);
                let mut shutdown_signal = shutdown_rx.clone();
                async move {
                    let incoming = TcpListener::bind(&addr).await.unwrap();
                    let service =
                        service_fn(move |req| handle_request_h2(req, Arc::clone(&cache), ssl_port));

                    info!("h2: listening at {}", addr);

                    loop {
                        tokio::select! {
                            _ = shutdown_signal.changed() => {
                                info!("h2: got shutdown signal!");
                                break;
                            }
                            result = incoming.accept() => {
                                let (tcp_stream, _remote_addr) = result.unwrap();
                                let tls_acceptor = tls_acceptor.clone();
                                let service = service.clone();

                                tokio::spawn(async move {
                                    let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                                        Ok(tls_stream) => tls_stream,
                                        Err(err) => {
                                            error!("h2: failed to perform tls handshake: {err:#}");
                                            return;
                                        }
                                    };
                                    if let Err(err) = ConnectionBuilder::new(TokioExecutor::new())
                                        .serve_connection(TokioIo::new(tls_stream), service)
                                        .await
                                    {
                                        error!("h2: failed to serve connection: {err:#}");
                                    }
                                });
                            }
                        }
                    }

                    info!("Shutdown h2!");
                }
            };

            tokio::spawn(srv_h2);
        }

        let certs = certs_from_base64(&self.fullchain_pem_base64)?;
        let key = privkey_from_base64(&self.privkey_pem_base64)?;
        let mut tls_config = rustls::ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();

        tls_config.max_early_data_size = u32::MAX;
        let alpn: Vec<Vec<u8>> = vec![b"h3".to_vec()];
        tls_config.alpn_protocols = alpn;

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_config));
        let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), self.ssl_port);
        let endpoint = quinn::Endpoint::server(server_config, addr).unwrap();

        let srv_h3 = {
            let cache = Arc::clone(&self.cache);
            let mut shutdown_signal = shutdown_rx.clone();

            async move {
                loop {
                    tokio::select! {
                        _ = shutdown_signal.changed() => {
                                info!("h3: got shutdown signal!");
                                break;
                        }
                        res = endpoint.accept()  => {
                            if let Some(new_conn) = res {
                                let cache = Arc::clone(&cache);
                                tokio::spawn(async move {
                                    match new_conn.await {
                                        Ok(conn) => {
                                            let h3_conn = h3::server::builder()
                                                .enable_connect(true)
                                                .send_grease(true)
                                                .build(h3_quinn::Connection::new(conn))
                                                .await
                                                .unwrap();

                                                tokio::spawn(async move {
                                                    if let Err(err) = handle_connection(h3_conn, cache).await {
                                                        tracing::error!("h3: failed to handle connection: {err:?}");
                                                    }
                                                });
                                        }
                                        Err(err) => {
                                            error!("h3: accepting connection failed: {:?}", err);
                                        }

                                    }
                                });
                            }
                        }
                    }
                }

                info!("Shutdown h3!");

                fin_tx.send(())
            }
        };

        tokio::spawn(srv_h3);
        let _ = up_tx.send(());
        Ok((up_rx, fin_rx, shutdown_tx))
    }
}

async fn handle_connection(
    mut conn: Connection<h3_quinn::Connection, Bytes>,
    cache: Arc<Cache>,
) -> Result<()> {
    loop {
        match conn.accept().await {
            Ok(Some((req, stream))) => {
                let cache = Arc::clone(&cache);
                tokio::spawn(async move {
                    if let Err(e) = handle_request_h3(req, stream, cache).await {
                        error!("Handling request failed: {}", e);
                    }
                });
            }
            Ok(None) => {
                info!("Connection closed gracefully");
                break;
            }
            Err(err) => {
                info!("Connection error: {}", err);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_request_h2(
    req: http::Request<Incoming>,
    cache: Arc<Cache>,
    ssl_port: u16,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let (status, data, content_type, content_encoding) = request_handler(
        req.method(),
        req.uri().path(),
        req.uri().query(),
        cache.clone(),
    )
    .await?;
    if let (Some(data), Some(content_type)) = (data, content_type) {
        let mut response = Response::new(Full::from(data.0));
        *response.status_mut() = status;
        response.headers_mut().insert(
            "alt-srv",
            format!("h3=\":{}\"; ma=2592000", ssl_port).parse().unwrap(),
        );
        response
            .headers_mut()
            .insert("content-type", content_type.parse().unwrap());
        response
            .headers_mut()
            .insert("etag", format!("{}", data.1).parse().unwrap());

        if content_type == "application/vnd.apple.mpegurl" {
            response
                .headers_mut()
                .insert("content-encoding", "gzip".parse().unwrap());
            response
                .headers_mut()
                .insert("vary", "accept-encoding".parse().unwrap());
        }
        add_cors_headers(&mut response);
        Ok(response)
    } else {
        let mut response = Response::new(Full::default());
        *response.status_mut() = status;
        response.headers_mut().insert(
            "alt-srv",
            format!("h3=\":{}\"; ma=2592000", ssl_port).parse().unwrap(),
        );
        add_cors_headers(&mut response);
        Ok(response)
    }
}

async fn handle_request_h3(
    req: http::Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    cache: Arc<Cache>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (status, data, content_type, content_encoding) =
        request_handler(req.method(), req.uri().path(), req.uri().query(), cache).await?;

    if let (Some(data), Some(content_type)) = (data, content_type) {
        let mut r = http::Response::builder()
            .status(status)
            .header("content-type", content_type.clone())
            .header("etag", data.1);
        if content_type == "application/vnd.apple.mpegurl" {
            r = r
                .header("content-encoding", "gzip")
                .header("vary", "accept-encoding");
        }
        let resp = r.body(()).unwrap();

        match stream.send_response(resp).await {
            Ok(_) => {}
            Err(err) => {
                error!("unable to send response to connection peer: {:?}", err);
            }
        }

        stream.send_data(data.0).await?;
    } else {
        let resp = http::Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .body(())
            .unwrap();

        match stream.send_response(resp).await {
            Ok(_) => {}
            Err(err) => {
                error!("unable to send response to connection peer: {:?}", err);
            }
        }
    }

    if let Err(e) = stream.finish().await {
        error!("Error finishing stream: {}", e);
        // Decide whether to return the error or ignore it
        // For now, we'll return the error to propagate it
        return Err(e.into());
    }

    Ok(())
}

async fn request_handler(
    method: &Method,
    path: &str,
    query: Option<&str>,
    cache: Arc<Cache>,
) -> Result<
    (
        StatusCode,
        Option<(Bytes, u64)>,
        Option<String>,
        Option<String>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let res = match (method, path) {
        (&Method::OPTIONS, _) => (StatusCode::OK, None, None, None),
        (&Method::HEAD, path) => (StatusCode::NOT_IMPLEMENTED, None, None, None),
        (&Method::GET, path) => {
            let keys: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

            let accepts_gzip = true;

            if keys.is_empty() {
                (StatusCode::NOT_FOUND, None, None, None)
            } else if keys[0] == "up" {
                (
                    StatusCode::OK,
                    Some((Bytes::from("OK"), 0)),
                    Some("text/plain".into()),
                    None,
                )
            } else {
                match cache.get_bytes(path, accepts_gzip).await {
                    Ok((bytes, etag, mime_type, is_compressed)) => {
                        let content_encoding = if is_compressed {
                            Some("gzip".to_string())
                        } else {
                            None
                        };

                        (
                            StatusCode::OK,
                            Some((bytes, etag)),
                            Some(mime_type),
                            content_encoding,
                        )
                    }
                    Err(e) => {
                        if e.to_string().contains("File not found") {
                            (StatusCode::NOT_FOUND, None, None, None)
                        } else if e.to_string().contains("Directory traversal") {
                            (StatusCode::FORBIDDEN, None, None, None)
                        } else {
                            (StatusCode::INTERNAL_SERVER_ERROR, None, None, None)
                        }
                    }
                }
            }
        }
        _ => (StatusCode::METHOD_NOT_ALLOWED, None, None, None),
    };

    Ok(res)
}

fn add_cors_headers(res: &mut http::Response<http_body_util::Full<Bytes>>) {
    res.headers_mut()
        .insert("access-control-allow-origin", "*".parse().unwrap());
    res.headers_mut().insert(
        "access-control-allow-methods",
        "GET, OPTIONS".parse().unwrap(),
    );
    res.headers_mut()
        .insert("access-control-allow-headers", "*".parse().unwrap());
}

use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use mime_guess;
use path_clean::PathClean;
use std::collections::HashMap;
use std::error::Error;
use std::io::Write;
use std::path::PathBuf;
use tokio::fs;
use tokio::sync::RwLock;
use tracing::error;
use xxhash_rust::const_xxh3::xxh3_64 as const_xxh3;

struct CacheEntry {
    uncompressed_bytes: Bytes,
    compressed_bytes: Option<Bytes>,
    etag: u64,
    mime_type: String,
}

pub(crate) struct Cache {
    cache: RwLock<HashMap<String, CacheEntry>>,
    public_folder: PathBuf,
}

impl Cache {
    pub(crate) fn new(public_folder: PathBuf) -> Self {
        Cache {
            public_folder,
            cache: RwLock::new(HashMap::new()),
        }
    }

    fn should_compress(mime_type: &str) -> bool {
        let compressible_types = [
            "text/",
            "application/javascript",
            "application/json",
            "application/xml",
            "application/x-yaml",
            "application/graphql",
            "application/x-www-form-urlencoded",
            "application/ld+json",
            "application/manifest+json",
            "image/svg+xml",
        ];

        compressible_types
            .iter()
            .any(|&prefix| mime_type.starts_with(prefix))
    }

    fn compress_data(data: &[u8]) -> Result<Bytes, Box<dyn Error + Send + Sync>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)?;
        Ok(Bytes::from(encoder.finish()?))
    }

    pub(crate) async fn get_bytes(
        &self,
        path: &str,
        accepts_gzip: bool,
    ) -> Result<(Bytes, u64, String, bool), Box<dyn Error + Send + Sync>> {
        if let Some(entry) = self.cache.read().await.get(path) {
            if accepts_gzip && entry.compressed_bytes.is_some() {
                return Ok((
                    entry.compressed_bytes.as_ref().unwrap().clone(),
                    entry.etag,
                    entry.mime_type.clone(),
                    true,
                ));
            }
            return Ok((
                entry.uncompressed_bytes.clone(),
                entry.etag,
                entry.mime_type.clone(),
                false,
            ));
        }

        let trimmed_path = path.trim_start_matches('/');

        let file_path = if trimmed_path.is_empty() {
            self.public_folder.join("index.html")
        } else {
            self.public_folder.join(trimmed_path)
        };

        tracing::debug!("Constructed file path: {:?}", file_path);

        if !file_path.exists() {
            tracing::debug!("File not found: {:?}", file_path);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not found",
            )));
        }

        let sanitized_path = file_path.clean();
        let public_path = self.public_folder.clean();

        if !sanitized_path.starts_with(&public_path) {
            error!(
                "Attempted directory traversal attack: requested path {:?} is outside of public_folder {:?}",
                sanitized_path, public_path
            );
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Directory traversal attempt detected",
            )));
        }

        match fs::read(&sanitized_path).await {
            Ok(contents) => {
                let mime_type = mime_guess::from_path(&sanitized_path)
                    .first_or_octet_stream()
                    .to_string();

                let uncompressed_data = Bytes::from(contents);
                let etag = const_xxh3(&uncompressed_data);

                let compressed_data = if Self::should_compress(&mime_type) {
                    match Self::compress_data(&uncompressed_data) {
                        Ok(compressed) => Some(compressed),
                        Err(e) => {
                            error!("Failed to compress data: {}", e);
                            None
                        }
                    }
                } else {
                    None
                };

                let entry = CacheEntry {
                    uncompressed_bytes: uncompressed_data.clone(),
                    compressed_bytes: compressed_data.clone(),
                    etag,
                    mime_type: mime_type.clone(),
                };

                self.cache.write().await.insert(path.to_string(), entry);

                if accepts_gzip && compressed_data.is_some() {
                    Ok((compressed_data.unwrap(), etag, mime_type, true))
                } else {
                    Ok((uncompressed_data, etag, mime_type, false))
                }
            }
            Err(err) => {
                error!("Error reading file {:?}: {}", sanitized_path, err);
                Err(Box::new(err))
            }
        }
    }
}

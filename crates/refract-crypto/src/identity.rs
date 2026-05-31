//! Persistent self-signed ECDSA P-256 identity handling.
//!
//! Startup loads an existing PEM bundle or generates a new rcgen ECDSA P-256
//! certificate and persists it for stable SDP fingerprints across restarts.
//!
//! # Examples
//!
//! ```
//! # use std::fs;
//! # use refract_crypto::Identity;
//! # let path = std::env::temp_dir().join("refract-crypto-identity-example.pem");
//! # let _ = fs::remove_file(&path);
//! let identity = Identity::load_or_generate(&path)?;
//! assert_eq!(identity.fingerprint().as_bytes().len(), 32);
//! # let _ = fs::remove_file(identity.path());
//! # Ok::<(), refract_crypto::CryptoError>(())
//! ```

use std::{
    fmt, fs,
    io::Write,
    path::{Path, PathBuf},
};

use rcgen::generate_simple_self_signed;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sha2::{Digest, Sha256};

use crate::{
    Stability,
    error::{CryptoError, CryptoResult},
};

const IDENTITY_SUBJECT: &str = "refract.local";

/// SHA-256 certificate fingerprint exposed in SDP.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Fingerprint {
    bytes: [u8; 32],
}

impl Fingerprint {
    /// Creates a fingerprint from certificate DER bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::Fingerprint;
    /// let fingerprint = Fingerprint::from_der(b"certificate");
    /// assert_eq!(fingerprint.as_bytes().len(), 32);
    /// ```
    #[must_use]
    pub fn from_der(der: &[u8]) -> Self {
        let digest = Sha256::digest(der);
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        Self { bytes }
    }

    /// Returns the raw SHA-256 digest bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::Fingerprint;
    /// assert_eq!(Fingerprint::from_der(b"certificate").as_bytes().len(), 32);
    /// ```
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.bytes
    }

    /// Returns the SDP hash algorithm label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::Fingerprint;
    /// assert_eq!(Fingerprint::algorithm(), "sha-256");
    /// ```
    #[must_use]
    pub const fn algorithm() -> &'static str {
        "sha-256"
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{Fingerprint, Stability};
    /// assert_eq!(
    ///     Fingerprint::from_der(b"certificate").stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.bytes.iter().enumerate() {
            if index > 0 {
                formatter.write_str(":")?;
            }
            write!(formatter, "{byte:02X}")?;
        }
        Ok(())
    }
}

/// Persistent self-signed `DTLS` identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    path: PathBuf,
    certificate_pem: String,
    private_key_pem: String,
    fingerprint: Fingerprint,
}

impl Identity {
    /// Loads the persistent identity or generates and persists a new ECDSA P-256 identity.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs;
    /// # use refract_crypto::Identity;
    /// # let path = std::env::temp_dir().join("refract-crypto-load-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let first = Identity::load_or_generate(&path)?;
    /// let second = Identity::load_or_generate(&path)?;
    /// assert_eq!(first.fingerprint(), second.fingerprint());
    /// # let _ = fs::remove_file(first.path());
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the identity cannot be read, parsed, generated, or persisted.
    pub fn load_or_generate(path: impl AsRef<Path>) -> CryptoResult<Self> {
        let path = path.as_ref();
        if path.exists() {
            return Self::load(path);
        }
        Self::generate(path)
    }

    /// Loads an identity from a persisted PEM bundle.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs;
    /// # use refract_crypto::Identity;
    /// # let path = std::env::temp_dir().join("refract-crypto-load-only-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let generated = Identity::load_or_generate(&path)?;
    /// let loaded = Identity::load(generated.path())?;
    /// assert_eq!(generated.fingerprint(), loaded.fingerprint());
    /// # let _ = fs::remove_file(generated.path());
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or does not contain a certificate and key.
    pub fn load(path: impl AsRef<Path>) -> CryptoResult<Self> {
        let path = path.as_ref();
        let pem = fs::read_to_string(path).map_err(|source| CryptoError::IdentityIo {
            operation: "read",
            path: path.display().to_string(),
            source,
        })?;
        Self::from_pem_bundle(path.to_path_buf(), &pem)
    }

    /// Generates and persists a new self-signed ECDSA P-256 identity.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs;
    /// # use refract_crypto::Identity;
    /// # let path = std::env::temp_dir().join("refract-crypto-generate-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let identity = Identity::generate(&path)?;
    /// assert!(identity.path().exists());
    /// # let _ = fs::remove_file(identity.path());
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if certificate generation or atomic persistence fails.
    pub fn generate(path: impl AsRef<Path>) -> CryptoResult<Self> {
        let path = path.as_ref();
        let certified = generate_simple_self_signed([IDENTITY_SUBJECT.to_owned()])?;
        let certificate_pem = certified.cert.pem();
        let private_key_pem = certified.signing_key.serialize_pem();
        let mut pem = String::new();
        pem.try_reserve_exact(certificate_pem.len() + private_key_pem.len())
            .map_err(|_| CryptoError::Exporter {
                message: "identity pem allocation failed",
            })?;
        pem.push_str(&certificate_pem);
        pem.push_str(&private_key_pem);
        persist_identity(path, pem.as_bytes())?;
        Self::from_parts(path.to_path_buf(), certificate_pem, private_key_pem)
    }

    /// Returns the path where the identity is persisted.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::Identity;
    /// # let identity = Identity::load_or_generate(std::env::temp_dir().join("refract-crypto-path-example.pem"))?;
    /// assert!(identity.path().ends_with("refract-crypto-path-example.pem"));
    /// # let _ = std::fs::remove_file(identity.path());
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the PEM certificate.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::Identity;
    /// # let identity = Identity::load_or_generate(std::env::temp_dir().join("refract-crypto-cert-example.pem"))?;
    /// assert!(identity.certificate_pem().contains("BEGIN CERTIFICATE"));
    /// # let _ = std::fs::remove_file(identity.path());
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    /// Returns the PEM private key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::Identity;
    /// # let identity = Identity::load_or_generate(std::env::temp_dir().join("refract-crypto-key-example.pem"))?;
    /// assert!(identity.private_key_pem().contains("BEGIN PRIVATE KEY"));
    /// # let _ = std::fs::remove_file(identity.path());
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }

    /// Returns the SHA-256 certificate fingerprint.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::Identity;
    /// # let identity = Identity::load_or_generate(std::env::temp_dir().join("refract-crypto-fp-example.pem"))?;
    /// assert_eq!(identity.fingerprint().as_bytes().len(), 32);
    /// # let _ = std::fs::remove_file(identity.path());
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{Identity, Stability};
    /// # let identity = Identity::load_or_generate(std::env::temp_dir().join("refract-crypto-stability-example.pem"))?;
    /// assert_eq!(identity.stability(), Stability::Stage1);
    /// # let _ = std::fs::remove_file(identity.path());
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn from_pem_bundle(path: PathBuf, pem: &str) -> CryptoResult<Self> {
        let certificate = CertificateDer::from_pem_slice(pem.as_bytes()).map_err(|_| {
            CryptoError::IdentityParse {
                path: path.display().to_string(),
                message: "missing certificate pem",
            }
        })?;
        PrivateKeyDer::from_pem_slice(pem.as_bytes())
            .map_err(|_| CryptoError::IdentityParse {
                path: path.display().to_string(),
                message: "missing private key pem",
            })
            .map(|_| ())?;
        let certificate_pem = pem_section(pem, "CERTIFICATE", path.as_path())?;
        let private_key_pem = pem_section(pem, "PRIVATE KEY", path.as_path())?;
        let fingerprint = Fingerprint::from_der(certificate.as_ref());
        Ok(Self {
            path,
            certificate_pem,
            private_key_pem,
            fingerprint,
        })
    }

    fn from_parts(
        path: PathBuf,
        certificate_pem: String,
        private_key_pem: String,
    ) -> CryptoResult<Self> {
        let certificate =
            CertificateDer::from_pem_slice(certificate_pem.as_bytes()).map_err(|_| {
                CryptoError::IdentityParse {
                    path: path.display().to_string(),
                    message: "invalid generated certificate",
                }
            })?;
        let fingerprint = Fingerprint::from_der(certificate.as_ref());
        Ok(Self {
            path,
            certificate_pem,
            private_key_pem,
            fingerprint,
        })
    }
}

fn pem_section(pem: &str, label: &'static str, path: &Path) -> CryptoResult<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem.find(&begin).ok_or_else(|| CryptoError::IdentityParse {
        path: path.display().to_string(),
        message: "missing pem begin marker",
    })?;
    let end_start = pem.find(&end).ok_or_else(|| CryptoError::IdentityParse {
        path: path.display().to_string(),
        message: "missing pem end marker",
    })?;
    let end_index = end_start
        .checked_add(end.len())
        .ok_or_else(|| CryptoError::IdentityParse {
            path: path.display().to_string(),
            message: "pem marker overflow",
        })?;
    let mut section = pem
        .get(start..end_index)
        .ok_or_else(|| CryptoError::IdentityParse {
            path: path.display().to_string(),
            message: "invalid pem marker order",
        })?
        .to_owned();
    section.push('\n');
    Ok(section)
}

fn persist_identity(path: &Path, pem: &[u8]) -> CryptoResult<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| CryptoError::IdentityIo {
            operation: "create_dir_all",
            path: parent.display().to_string(),
            source,
        })?;
    }

    let temp_path = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&temp_path).map_err(|source| CryptoError::IdentityIo {
            operation: "create",
            path: temp_path.display().to_string(),
            source,
        })?;
        file.write_all(pem)
            .map_err(|source| CryptoError::IdentityIo {
                operation: "write",
                path: temp_path.display().to_string(),
                source,
            })?;
        file.sync_all().map_err(|source| CryptoError::IdentityIo {
            operation: "sync",
            path: temp_path.display().to_string(),
            source,
        })?;
    }
    fs::rename(&temp_path, path).map_err(|source| CryptoError::IdentityIo {
        operation: "rename",
        path: path.display().to_string(),
        source,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_display_is_sdp_format() {
        let fingerprint = Fingerprint { bytes: [0xab; 32] };

        assert_eq!(
            fingerprint.to_string(),
            "AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB"
        );
    }

    #[test]
    fn identity_is_stable_across_restarts() -> CryptoResult<()> {
        let dir = tempfile::tempdir().map_err(|source| CryptoError::IdentityIo {
            operation: "tempdir",
            path: "tempdir".to_owned(),
            source,
        })?;
        let path = dir.path().join("identity.pem");

        let first = Identity::load_or_generate(&path)?;
        let second = Identity::load_or_generate(&path)?;

        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.certificate_pem(), second.certificate_pem());
        Ok(())
    }
}

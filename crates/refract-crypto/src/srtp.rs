//! `DTLS-SRTP` protection-profile negotiation and key exporter splitting.
//!
//! Only RFC 7714 AEAD AES-GCM profiles are accepted. Exported keying material
//! is split in RFC 5764 order: client key, server key, client salt, server salt.
//!
//! # Examples
//!
//! ```
//! # use refract_crypto::{ExporterMaterial, SrtpProtectionProfile};
//! let profile = SrtpProtectionProfile::AeadAes128Gcm;
//! let material = ExporterMaterial::new(profile, &[7_u8; 56])?;
//! let keys = material.into_srtp_keys()?;
//! assert_eq!(keys.client_key().len(), 16);
//! assert_eq!(keys.client_salt().len(), 12);
//! # Ok::<(), refract_crypto::CryptoError>(())
//! ```

use crate::{
    Stability,
    error::{CryptoError, CryptoResult},
};

const AES_128_GCM_PROFILE: u16 = 0x0007;
const AES_256_GCM_PROFILE: u16 = 0x0008;
const AES_128_KEY_LEN: usize = 16;
const AES_256_KEY_LEN: usize = 32;
const GCM_SALT_LEN: usize = 12;
const AES_128_EXPORTER_LEN: usize = (AES_128_KEY_LEN * 2) + (GCM_SALT_LEN * 2);
const AES_256_EXPORTER_LEN: usize = (AES_256_KEY_LEN * 2) + (GCM_SALT_LEN * 2);
const MAX_EXPORTER_LEN: usize = AES_256_EXPORTER_LEN;

/// RFC 5764 exporter label for `DTLS-SRTP`.
pub const DTLS_SRTP_EXPORTER_LABEL: &[u8] = b"EXTRACTOR-dtls_srtp";

/// Accepted `DTLS-SRTP` protection profiles.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SrtpProtectionProfile {
    /// `SRTP_AEAD_AES_128_GCM`.
    AeadAes128Gcm,
    /// `SRTP_AEAD_AES_256_GCM`.
    AeadAes256Gcm,
}

impl SrtpProtectionProfile {
    /// Returns the IANA protection profile identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::SrtpProtectionProfile;
    /// assert_eq!(SrtpProtectionProfile::AeadAes128Gcm.id(), 0x0007);
    /// ```
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::AeadAes128Gcm => AES_128_GCM_PROFILE,
            Self::AeadAes256Gcm => AES_256_GCM_PROFILE,
        }
    }

    /// Returns the stable profile name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::SrtpProtectionProfile;
    /// assert_eq!(
    ///     SrtpProtectionProfile::AeadAes256Gcm.as_str(),
    ///     "SRTP_AEAD_AES_256_GCM"
    /// );
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AeadAes128Gcm => "SRTP_AEAD_AES_128_GCM",
            Self::AeadAes256Gcm => "SRTP_AEAD_AES_256_GCM",
        }
    }

    /// Returns the SRTP master key length in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::SrtpProtectionProfile;
    /// assert_eq!(SrtpProtectionProfile::AeadAes128Gcm.key_len(), 16);
    /// ```
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::AeadAes128Gcm => AES_128_KEY_LEN,
            Self::AeadAes256Gcm => AES_256_KEY_LEN,
        }
    }

    /// Returns the SRTP master salt length in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::SrtpProtectionProfile;
    /// assert_eq!(SrtpProtectionProfile::AeadAes128Gcm.salt_len(), 12);
    /// ```
    #[must_use]
    pub const fn salt_len(self) -> usize {
        GCM_SALT_LEN
    }

    /// Returns the required exporter material length.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::SrtpProtectionProfile;
    /// assert_eq!(SrtpProtectionProfile::AeadAes128Gcm.exporter_len(), 56);
    /// ```
    #[must_use]
    pub const fn exporter_len(self) -> usize {
        match self {
            Self::AeadAes128Gcm => AES_128_EXPORTER_LEN,
            Self::AeadAes256Gcm => AES_256_EXPORTER_LEN,
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{SrtpProtectionProfile, Stability};
    /// assert_eq!(
    ///     SrtpProtectionProfile::AeadAes128Gcm.stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl TryFrom<u16> for SrtpProtectionProfile {
    type Error = CryptoError;

    fn try_from(profile: u16) -> Result<Self, Self::Error> {
        match profile {
            AES_128_GCM_PROFILE => Ok(Self::AeadAes128Gcm),
            AES_256_GCM_PROFILE => Ok(Self::AeadAes256Gcm),
            _ => Err(CryptoError::UnsupportedSrtpProfile { profile }),
        }
    }
}

/// Bounded RFC 5705 exporter material for the selected SRTP profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExporterMaterial {
    profile: SrtpProtectionProfile,
    bytes: [u8; MAX_EXPORTER_LEN],
    len: usize,
}

impl ExporterMaterial {
    /// Creates exporter material after validating the profile-specific length.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{ExporterMaterial, SrtpProtectionProfile};
    /// let material = ExporterMaterial::new(SrtpProtectionProfile::AeadAes128Gcm, &[0_u8; 56])?;
    /// assert_eq!(material.as_bytes().len(), 56);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the exporter length does not match the selected profile.
    pub fn new(profile: SrtpProtectionProfile, material: &[u8]) -> CryptoResult<Self> {
        let expected = profile.exporter_len();
        if material.len() != expected {
            return Err(CryptoError::InvalidExporterLength {
                profile: profile.as_str(),
                len: material.len(),
                expected,
            });
        }
        let mut bytes = [0_u8; MAX_EXPORTER_LEN];
        bytes[..expected].copy_from_slice(material);
        Ok(Self {
            profile,
            bytes,
            len: expected,
        })
    }

    /// Returns the selected SRTP profile.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{ExporterMaterial, SrtpProtectionProfile};
    /// let material = ExporterMaterial::new(SrtpProtectionProfile::AeadAes128Gcm, &[0_u8; 56])?;
    /// assert_eq!(material.profile(), SrtpProtectionProfile::AeadAes128Gcm);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn profile(&self) -> SrtpProtectionProfile {
        self.profile
    }

    /// Returns the bounded exporter bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{ExporterMaterial, SrtpProtectionProfile};
    /// let material = ExporterMaterial::new(SrtpProtectionProfile::AeadAes128Gcm, &[1_u8; 56])?;
    /// assert_eq!(material.as_bytes()[0], 1);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Splits exporter material into SRTP keys.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{ExporterMaterial, SrtpProtectionProfile};
    /// let keys = ExporterMaterial::new(SrtpProtectionProfile::AeadAes128Gcm, &[2_u8; 56])?
    ///     .into_srtp_keys()?;
    /// assert_eq!(keys.server_key().len(), 16);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the material length is no longer valid for the selected profile.
    pub fn into_srtp_keys(self) -> CryptoResult<SrtpKeys> {
        SrtpKeys::from_exporter(self.profile, self.as_bytes())
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{ExporterMaterial, SrtpProtectionProfile, Stability};
    /// let material = ExporterMaterial::new(SrtpProtectionProfile::AeadAes128Gcm, &[0_u8; 56])?;
    /// assert_eq!(material.stability(), Stability::Stage1);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// SRTP master keys and salts exported from a completed `DTLS` handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SrtpKeys {
    profile: SrtpProtectionProfile,
    client_key: [u8; AES_256_KEY_LEN],
    server_key: [u8; AES_256_KEY_LEN],
    client_salt: [u8; GCM_SALT_LEN],
    server_salt: [u8; GCM_SALT_LEN],
}

impl SrtpKeys {
    /// Splits exporter material in RFC 5764 order.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{SrtpKeys, SrtpProtectionProfile};
    /// let keys = SrtpKeys::from_exporter(SrtpProtectionProfile::AeadAes128Gcm, &[3_u8; 56])?;
    /// assert_eq!(keys.client_key().len(), 16);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the exporter material length does not match the profile.
    pub fn from_exporter(
        profile: SrtpProtectionProfile,
        exporter_material: &[u8],
    ) -> CryptoResult<Self> {
        let expected = profile.exporter_len();
        if exporter_material.len() != expected {
            return Err(CryptoError::InvalidExporterLength {
                profile: profile.as_str(),
                len: exporter_material.len(),
                expected,
            });
        }

        let key_len = profile.key_len();
        let salt_len = profile.salt_len();
        let server_key_start = key_len;
        let client_salt_start = server_key_start + key_len;
        let server_salt_start = client_salt_start + salt_len;

        let mut client_key = [0_u8; AES_256_KEY_LEN];
        let mut server_key = [0_u8; AES_256_KEY_LEN];
        let mut client_salt = [0_u8; GCM_SALT_LEN];
        let mut server_salt = [0_u8; GCM_SALT_LEN];

        client_key[..key_len].copy_from_slice(&exporter_material[..key_len]);
        server_key[..key_len]
            .copy_from_slice(&exporter_material[server_key_start..client_salt_start]);
        client_salt.copy_from_slice(&exporter_material[client_salt_start..server_salt_start]);
        server_salt.copy_from_slice(&exporter_material[server_salt_start..expected]);

        Ok(Self {
            profile,
            client_key,
            server_key,
            client_salt,
            server_salt,
        })
    }

    /// Returns the selected SRTP profile.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{SrtpKeys, SrtpProtectionProfile};
    /// let keys = SrtpKeys::from_exporter(SrtpProtectionProfile::AeadAes128Gcm, &[0_u8; 56])?;
    /// assert_eq!(keys.profile(), SrtpProtectionProfile::AeadAes128Gcm);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn profile(&self) -> SrtpProtectionProfile {
        self.profile
    }

    /// Returns the client SRTP master key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{SrtpKeys, SrtpProtectionProfile};
    /// let keys = SrtpKeys::from_exporter(SrtpProtectionProfile::AeadAes256Gcm, &[0_u8; 88])?;
    /// assert_eq!(keys.client_key().len(), 32);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub fn client_key(&self) -> &[u8] {
        &self.client_key[..self.profile.key_len()]
    }

    /// Returns the server SRTP master key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{SrtpKeys, SrtpProtectionProfile};
    /// let keys = SrtpKeys::from_exporter(SrtpProtectionProfile::AeadAes128Gcm, &[0_u8; 56])?;
    /// assert_eq!(keys.server_key().len(), 16);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub fn server_key(&self) -> &[u8] {
        &self.server_key[..self.profile.key_len()]
    }

    /// Returns the client SRTP master salt.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{SrtpKeys, SrtpProtectionProfile};
    /// let keys = SrtpKeys::from_exporter(SrtpProtectionProfile::AeadAes128Gcm, &[0_u8; 56])?;
    /// assert_eq!(keys.client_salt().len(), 12);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn client_salt(&self) -> &[u8] {
        &self.client_salt
    }

    /// Returns the server SRTP master salt.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{SrtpKeys, SrtpProtectionProfile};
    /// let keys = SrtpKeys::from_exporter(SrtpProtectionProfile::AeadAes128Gcm, &[0_u8; 56])?;
    /// assert_eq!(keys.server_salt().len(), 12);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn server_salt(&self) -> &[u8] {
        &self.server_salt
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{SrtpKeys, SrtpProtectionProfile, Stability};
    /// let keys = SrtpKeys::from_exporter(SrtpProtectionProfile::AeadAes128Gcm, &[0_u8; 56])?;
    /// assert_eq!(keys.stability(), Stability::Stage1);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_aead_profiles() {
        let error = SrtpProtectionProfile::try_from(0x0001).expect_err("profile is rejected");

        assert_eq!(error.error_code(), "HSF-CRY-002");
    }

    #[test]
    fn rfc5705_exporter_material_splits_in_rfc5764_order() -> CryptoResult<()> {
        let material = (0_u8..56).collect::<Vec<_>>();
        let keys = SrtpKeys::from_exporter(SrtpProtectionProfile::AeadAes128Gcm, &material)?;

        assert_eq!(keys.client_key(), &material[0..16]);
        assert_eq!(keys.server_key(), &material[16..32]);
        assert_eq!(keys.client_salt(), &material[32..44]);
        assert_eq!(keys.server_salt(), &material[44..56]);
        Ok(())
    }

    #[test]
    fn aes256_profile_uses_88_exported_bytes() {
        assert_eq!(SrtpProtectionProfile::AeadAes256Gcm.exporter_len(), 88);
    }
}

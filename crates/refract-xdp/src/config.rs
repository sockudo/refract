//! Bounded configuration types for the Linux XDP loader.
//!
//! # Examples
//!
//! ```
//! use refract_xdp::{InterfaceName, ListenPort, XdpConfig};
//!
//! let config = XdpConfig::new(
//!     InterfaceName::try_from("eth0")?,
//!     ListenPort::try_from(50000)?,
//! );
//! assert_eq!(config.listen_port().get(), 50000);
//! # Ok::<(), refract_xdp::XdpError>(())
//! ```

use std::fmt;

use crate::{
    XdpError, XdpResult,
    wire::{DEFAULT_STUN_BURST, DEFAULT_STUN_RATE_PER_SECOND},
};

const MAX_INTERFACE_NAME_LEN: usize = 15;
const MIN_MEDIA_PORT: u16 = 1_024;

/// Linux network interface name accepted by the XDP loader.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceName(String);

impl InterfaceName {
    /// Returns the validated interface name.
    ///
    /// # Examples
    ///
    /// ```
    /// let name = refract_xdp::InterfaceName::try_from("eth0")?;
    /// assert_eq!(name.as_str(), "eth0");
    /// # Ok::<(), refract_xdp::XdpError>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<&str> for InterfaceName {
    type Error = XdpError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let is_valid = !value.is_empty()
            && value.len() <= MAX_INTERFACE_NAME_LEN
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
        if is_valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(XdpError::InvalidInterfaceName {
                name: value.to_owned(),
            })
        }
    }
}

/// UDP media port protected by the XDP program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ListenPort(u16);

impl ListenPort {
    /// Returns the validated UDP port.
    ///
    /// # Examples
    ///
    /// ```
    /// let port = refract_xdp::ListenPort::try_from(50000)?;
    /// assert_eq!(port.get(), 50000);
    /// # Ok::<(), refract_xdp::XdpError>(())
    /// ```
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for ListenPort {
    type Error = XdpError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if value >= MIN_MEDIA_PORT {
            Ok(Self(value))
        } else {
            Err(XdpError::InvalidListenPort { port: value })
        }
    }
}

/// STUN token bucket limits pushed to the eBPF config map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunRateLimit {
    rate_per_second: u32,
    burst: u32,
}

impl StunRateLimit {
    /// Creates a bounded STUN rate limit.
    ///
    /// # Examples
    ///
    /// ```
    /// let limit = refract_xdp::StunRateLimit::new(100, 100)?;
    /// assert_eq!(limit.rate_per_second(), 100);
    /// # Ok::<(), refract_xdp::XdpError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`XdpError::InvalidRateLimit`] when either bound is zero or the
    /// burst is lower than the refill rate.
    pub const fn new(rate_per_second: u32, burst: u32) -> XdpResult<Self> {
        if rate_per_second == 0 || burst < rate_per_second {
            return Err(XdpError::InvalidRateLimit {
                rate_per_second,
                burst,
            });
        }
        Ok(Self {
            rate_per_second,
            burst,
        })
    }

    /// Returns the token refill rate per second.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(refract_xdp::StunRateLimit::default().rate_per_second(), 100);
    /// ```
    #[must_use]
    pub const fn rate_per_second(self) -> u32 {
        self.rate_per_second
    }

    /// Returns the maximum token bucket depth.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(refract_xdp::StunRateLimit::default().burst(), 100);
    /// ```
    #[must_use]
    pub const fn burst(self) -> u32 {
        self.burst
    }
}

impl Default for StunRateLimit {
    fn default() -> Self {
        Self {
            rate_per_second: DEFAULT_STUN_RATE_PER_SECOND,
            burst: DEFAULT_STUN_BURST,
        }
    }
}

/// XDP attach strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMode {
    /// Driver/native XDP mode.
    Driver,
    /// Generic SKB XDP mode.
    Generic,
    /// Hardware offload XDP mode.
    Hardware,
}

/// Complete loader configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpConfig {
    interface: InterfaceName,
    listen_port: ListenPort,
    stun_limit: StunRateLimit,
    attach_mode: AttachMode,
}

impl XdpConfig {
    /// Creates a config with production defaults for STUN limiting.
    ///
    /// # Examples
    ///
    /// ```
    /// let config = refract_xdp::XdpConfig::new(
    ///     refract_xdp::InterfaceName::try_from("eth0")?,
    ///     refract_xdp::ListenPort::try_from(50000)?,
    /// );
    /// assert_eq!(config.stun_limit().burst(), 100);
    /// # Ok::<(), refract_xdp::XdpError>(())
    /// ```
    #[must_use]
    pub fn new(interface: InterfaceName, listen_port: ListenPort) -> Self {
        Self {
            interface,
            listen_port,
            stun_limit: StunRateLimit::default(),
            attach_mode: AttachMode::Driver,
        }
    }

    /// Returns a copy with a different STUN rate limit.
    ///
    /// # Examples
    ///
    /// ```
    /// let config = refract_xdp::XdpConfig::new(
    ///     refract_xdp::InterfaceName::try_from("eth0")?,
    ///     refract_xdp::ListenPort::try_from(50000)?,
    /// )
    /// .with_stun_limit(refract_xdp::StunRateLimit::new(200, 400)?);
    /// assert_eq!(config.stun_limit().rate_per_second(), 200);
    /// # Ok::<(), refract_xdp::XdpError>(())
    /// ```
    #[must_use]
    pub const fn with_stun_limit(mut self, stun_limit: StunRateLimit) -> Self {
        self.stun_limit = stun_limit;
        self
    }

    /// Returns a copy with a different attach mode.
    ///
    /// # Examples
    ///
    /// ```
    /// let config = refract_xdp::XdpConfig::new(
    ///     refract_xdp::InterfaceName::try_from("eth0")?,
    ///     refract_xdp::ListenPort::try_from(50000)?,
    /// )
    /// .with_attach_mode(refract_xdp::AttachMode::Generic);
    /// assert_eq!(config.attach_mode(), refract_xdp::AttachMode::Generic);
    /// # Ok::<(), refract_xdp::XdpError>(())
    /// ```
    #[must_use]
    pub const fn with_attach_mode(mut self, attach_mode: AttachMode) -> Self {
        self.attach_mode = attach_mode;
        self
    }

    /// Returns the target interface.
    ///
    /// # Examples
    ///
    /// ```
    /// let config = refract_xdp::XdpConfig::new(
    ///     refract_xdp::InterfaceName::try_from("eth0")?,
    ///     refract_xdp::ListenPort::try_from(50000)?,
    /// );
    /// assert_eq!(config.interface().as_str(), "eth0");
    /// # Ok::<(), refract_xdp::XdpError>(())
    /// ```
    #[must_use]
    pub const fn interface(&self) -> &InterfaceName {
        &self.interface
    }

    /// Returns the target UDP port.
    #[must_use]
    pub const fn listen_port(&self) -> ListenPort {
        self.listen_port
    }

    /// Returns the STUN token bucket limit.
    #[must_use]
    pub const fn stun_limit(&self) -> StunRateLimit {
        self.stun_limit
    }

    /// Returns the XDP attach strategy.
    #[must_use]
    pub const fn attach_mode(&self) -> AttachMode {
        self.attach_mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_interface_names() {
        assert!(InterfaceName::try_from("").is_err());
        assert!(InterfaceName::try_from("interface-name-too-long").is_err());
        assert!(InterfaceName::try_from("eth0/1").is_err());
    }

    #[test]
    fn accepts_common_interface_names() {
        assert_eq!(
            InterfaceName::try_from("eth0").map(|name| name.to_string()),
            Ok("eth0".to_owned())
        );
        assert!(InterfaceName::try_from("ens5f0.42").is_ok());
    }

    #[test]
    fn rejects_privileged_media_ports() {
        assert_eq!(
            ListenPort::try_from(53),
            Err(XdpError::InvalidListenPort { port: 53 })
        );
    }

    #[test]
    fn validates_rate_limits() {
        assert!(StunRateLimit::new(100, 100).is_ok());
        assert!(StunRateLimit::new(0, 100).is_err());
        assert!(StunRateLimit::new(100, 99).is_err());
    }
}

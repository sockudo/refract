//! Semantic identifier newtypes.

use core::fmt;

use rand::{TryRng, rngs::SysRng as OsRng};

use crate::{Error, Result, limits};

macro_rules! define_id {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);

        impl $name {
            /// Creates a deterministic identifier from two test-controlled
            /// parts.
            #[must_use]
            pub const fn from_parts(high: u32, low: u32) -> Self {
                Self(((high as u64) << limits::ID_LOW_BITS) | (low as u64))
            }

            /// Creates an identifier from its raw value.
            #[must_use]
            pub const fn from_raw(raw: u64) -> Self {
                Self(raw)
            }

            /// Creates a random identifier using the operating system random
            /// source.
            ///
            /// # Errors
            ///
            /// Returns [`Error::Internal`] if the operating system random source
            /// fails.
            ///
            /// # Examples
            ///
            /// ```
            /// use refract_core::SessionId;
            ///
            /// let id = SessionId::new_random()?;
            /// assert_ne!(id.raw(), 0);
            /// # Ok::<(), refract_core::Error>(())
            /// ```
            pub fn new_random() -> Result<Self> {
                OsRng
                    .try_next_u64()
                    .map(Self)
                    .map_err(|_source| Error::Internal {
                        component: "ids",
                        message: "operating system random source failed",
                    })
            }

            /// Returns the raw identifier value.
            #[must_use]
            pub const fn raw(self) -> u64 {
                self.0
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self::from_raw(value)
            }
        }

        impl From<$name> for u64 {
            fn from(value: $name) -> Self {
                value.raw()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let value = self.0;
                write!(
                    formatter,
                    concat!($prefix, "_{:0width$x}"),
                    value,
                    width = limits::ID_HEX_WIDTH
                )
            }
        }
    };
}

define_id!(SessionId, "sess", "Session identifier.");
define_id!(RoomId, "room", "Room identifier.");
define_id!(TrackId, "track", "Track identifier.");
define_id!(Ssrc, "ssrc", "Synchronization source identifier.");
define_id!(PeerId, "peer", "Peer identifier.");
define_id!(NodeId, "node", "Cluster node identifier.");

#[cfg(test)]
mod tests {
    use super::{NodeId, PeerId, RoomId, SessionId, Ssrc, TrackId};

    #[test]
    fn deterministic_parts_are_combined_stably() {
        let id = SessionId::from_parts(0x0000_0001, 0x0000_0002);

        assert_eq!(id.raw(), 0x0000_0001_0000_0002);
    }

    #[test]
    fn identifiers_display_with_domain_prefix() {
        assert_eq!(
            SessionId::from_raw(0x2a).to_string(),
            "sess_000000000000002a"
        );
        assert_eq!(RoomId::from_raw(0x2a).to_string(), "room_000000000000002a");
        assert_eq!(
            TrackId::from_raw(0x2a).to_string(),
            "track_000000000000002a"
        );
        assert_eq!(Ssrc::from_raw(0x2a).to_string(), "ssrc_000000000000002a");
        assert_eq!(PeerId::from_raw(0x2a).to_string(), "peer_000000000000002a");
        assert_eq!(NodeId::from_raw(0x2a).to_string(), "node_000000000000002a");
    }

    #[test]
    fn random_identifier_uses_system_rng() {
        let id = SessionId::new_random();

        assert!(id.is_ok());
    }
}

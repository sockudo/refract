//! Linux Aya loader for the refract XDP hardening program.
//!
//! # Examples
//!
//! ```no_run
//! # #[cfg(target_os = "linux")]
//! # {
//! use refract_xdp::{InterfaceName, ListenPort, LoadedXdp, XdpConfig};
//!
//! let config = XdpConfig::new(
//!     InterfaceName::try_from("eth0")?,
//!     ListenPort::try_from(50000)?,
//! );
//! let loaded =
//!     LoadedXdp::load_from_path(config, "target/bpfel-unknown-none/release/refract-xdp-ebpf")?;
//! let _stats = loaded.stats()?;
//! # }
//! # Ok::<(), refract_xdp::XdpError>(())
//! ```

use std::path::Path;

use aya::{
    Ebpf,
    maps::{Array, PerCpuArray},
    programs::{Xdp, XdpFlags, xdp::XdpLinkId},
};

use crate::{AttachMode, XdpConfig, XdpError, XdpResult, XdpStats, wire::STATS_COUNTERS};

const PROGRAM_NAME: &str = "refract_xdp";
const CONFIG_MAP: &str = "REFRACT_XDP_CONFIG";
const STATS_MAP: &str = "REFRACT_XDP_STATS";
const CONFIG_LISTEN_PORT: u32 = 0;
const CONFIG_STUN_RATE: u32 = 1;
const CONFIG_STUN_BURST: u32 = 2;
const CONFIG_ENTRIES: u32 = 3;

/// Loaded XDP program and its owned link.
#[derive(Debug)]
pub struct LoadedXdp {
    bpf: Ebpf,
    link_id: Option<XdpLinkId>,
    config: XdpConfig,
}

impl LoadedXdp {
    /// Loads, configures, and attaches the XDP program to the configured NIC.
    ///
    /// # Errors
    ///
    /// Returns [`XdpError`] when the object is missing, Aya cannot load the
    /// program, map configuration fails, or the attach operation fails.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn load_from_path(config: XdpConfig, object_path: impl AsRef<Path>) -> XdpResult<Self> {
        let path = object_path.as_ref();
        if !path.is_file() {
            return Err(XdpError::ObjectNotFound {
                path: path.display().to_string(),
            });
        }

        let mut bpf = Ebpf::load_file(path).map_err(|error| XdpError::Aya {
            operation: "load_file",
            message: error.to_string(),
        })?;
        configure_maps(&mut bpf, &config)?;

        let link_id = {
            let program: &mut Xdp = bpf
                .program_mut(PROGRAM_NAME)
                .ok_or_else(|| XdpError::Aya {
                    operation: "program_mut",
                    message: format!("program `{PROGRAM_NAME}` missing"),
                })?
                .try_into()
                .map_err(|error: aya::programs::ProgramError| XdpError::Aya {
                    operation: "program_type",
                    message: error.to_string(),
                })?;
            program.load().map_err(|error| XdpError::Aya {
                operation: "program_load",
                message: error.to_string(),
            })?;
            program
                .attach(
                    config.interface().as_str(),
                    attach_flags(config.attach_mode()),
                )
                .map_err(|error| XdpError::Aya {
                    operation: "program_attach",
                    message: error.to_string(),
                })?
        };

        Ok(Self {
            bpf,
            link_id: Some(link_id),
            config,
        })
    }

    /// Hot-reloads the STUN token bucket settings without detaching XDP.
    ///
    /// # Errors
    ///
    /// Returns [`XdpError`] when the config map update fails.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn update_rate_limit(&mut self, limit: crate::StunRateLimit) -> XdpResult<()> {
        self.config = self.config.clone().with_stun_limit(limit);
        configure_maps(&mut self.bpf, &self.config)
    }

    /// Returns counters summed across all CPUs.
    ///
    /// # Errors
    ///
    /// Returns [`XdpError`] when stats map lookup fails.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn stats(&self) -> XdpResult<XdpStats> {
        let stats_map = self.bpf.map(STATS_MAP).ok_or_else(|| XdpError::Aya {
            operation: "stats_map",
            message: format!("map `{STATS_MAP}` missing"),
        })?;
        let stats = PerCpuArray::<_, u64>::try_from(stats_map).map_err(|error| XdpError::Aya {
            operation: "stats_map_open",
            message: error.to_string(),
        })?;
        let mut counters = [0_u64; STATS_COUNTERS];

        for (index, value) in (0_u32..).zip(counters.iter_mut()) {
            let cpu_values = stats.get(&index, 0).map_err(|error| XdpError::Aya {
                operation: "stats_get",
                message: error.to_string(),
            })?;
            *value = cpu_values.iter().copied().sum();
        }

        Ok(XdpStats::from_counters(counters))
    }

    /// Detaches the XDP program from the NIC.
    ///
    /// # Errors
    ///
    /// Returns [`XdpError`] when Aya reports a detach failure.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn detach(&mut self) -> XdpResult<()> {
        let Some(link_id) = self.link_id.take() else {
            return Ok(());
        };
        let program: &mut Xdp = self
            .bpf
            .program_mut(PROGRAM_NAME)
            .ok_or_else(|| XdpError::Aya {
                operation: "program_mut_detach",
                message: format!("program `{PROGRAM_NAME}` missing"),
            })?
            .try_into()
            .map_err(|error: aya::programs::ProgramError| XdpError::Aya {
                operation: "program_type_detach",
                message: error.to_string(),
            })?;
        program.detach(link_id).map_err(|error| XdpError::Aya {
            operation: "program_detach",
            message: error.to_string(),
        })
    }
}

impl Drop for LoadedXdp {
    fn drop(&mut self) {
        drop(self.detach());
    }
}

fn configure_maps(bpf: &mut Ebpf, config: &XdpConfig) -> XdpResult<()> {
    let map = bpf.map_mut(CONFIG_MAP).ok_or_else(|| XdpError::Aya {
        operation: "config_map",
        message: format!("map `{CONFIG_MAP}` missing"),
    })?;
    let mut config_map = Array::<_, u64>::try_from(map).map_err(|error| XdpError::Aya {
        operation: "config_map_open",
        message: error.to_string(),
    })?;
    if config_map.len() < CONFIG_ENTRIES {
        return Err(XdpError::Aya {
            operation: "config_map_len",
            message: format!("expected at least {CONFIG_ENTRIES} entries"),
        });
    }
    config_map
        .set(CONFIG_LISTEN_PORT, u64::from(config.listen_port().get()), 0)
        .map_err(|error| XdpError::Aya {
            operation: "set_listen_port",
            message: error.to_string(),
        })?;
    config_map
        .set(
            CONFIG_STUN_RATE,
            u64::from(config.stun_limit().rate_per_second()),
            0,
        )
        .map_err(|error| XdpError::Aya {
            operation: "set_stun_rate",
            message: error.to_string(),
        })?;
    config_map
        .set(CONFIG_STUN_BURST, u64::from(config.stun_limit().burst()), 0)
        .map_err(|error| XdpError::Aya {
            operation: "set_stun_burst",
            message: error.to_string(),
        })
}

const fn attach_flags(mode: AttachMode) -> XdpFlags {
    match mode {
        AttachMode::Driver => XdpFlags::DRV_MODE,
        AttachMode::Generic => XdpFlags::SKB_MODE,
        AttachMode::Hardware => XdpFlags::HW_MODE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_modes_map_to_aya_flags() {
        assert_eq!(
            attach_flags(AttachMode::Driver).bits(),
            XdpFlags::DRV_MODE.bits()
        );
        assert_eq!(
            attach_flags(AttachMode::Generic).bits(),
            XdpFlags::SKB_MODE.bits()
        );
        assert_eq!(
            attach_flags(AttachMode::Hardware).bits(),
            XdpFlags::HW_MODE.bits()
        );
    }
}

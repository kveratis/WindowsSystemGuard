//! Known-noise rules. A rule only labels a group; the group keeps its counts, times and payloads.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::group::EventGroup;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoiseRule {
    /// Shown in reports as the reason a group was suppressed.
    pub name: String,
    pub provider: String,
    pub event_id: u16,
    /// When both are set, a payload field called `payload_key` must contain `payload_contains`.
    #[serde(default)]
    pub payload_key: Option<String>,
    #[serde(default)]
    pub payload_contains: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NoiseRules {
    #[serde(default, rename = "rule")]
    pub rules: Vec<NoiseRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Suppressed { rule: String },
    Surfaced,
}

#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error("cannot read or write {0}: {1}")]
    Io(String, std::io::Error),
    #[error("invalid noise rules: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("cannot encode noise rules: {0}")]
    Encode(#[from] toml::ser::Error),
}

fn rule(name: &str, provider: &str, event_id: u16) -> NoiseRule {
    NoiseRule { name: name.into(), provider: provider.into(), event_id, payload_key: None, payload_contains: None }
}

impl NoiseRules {
    /// The chatter this machine produces constantly and that has not pointed at a freeze.
    // shortcut: the plan's "Kernel-PnP 219 for WUDFRd after boot" has no boot time in a group, so
    // it matches every WUDFRd 219; add boot context to classify when that hides a real one.
    pub fn builtin() -> NoiseRules {
        let mut wudf = rule("Kernel-PnP 219 (WUDFRd driver load)", "Microsoft-Windows-Kernel-PnP", 219);
        wudf.payload_key = Some("DriverName".into());
        wudf.payload_contains = Some("WUDFRd".into());
        NoiseRules {
            rules: vec![
                rule("DCOM 10016 (permission settings)", "Microsoft-Windows-DistributedCOM", 10016),
                rule("Ntfs 98 (volume healthy)", "Microsoft-Windows-Ntfs", 98),
                rule("Tcpip 4266 (port exhaustion hint)", "Microsoft-Windows-TCPIP", 4266),
                rule("Firewall 2042", "Microsoft-Windows-Windows Firewall With Advanced Security", 2042),
                wudf,
            ],
        }
    }

    pub fn load(path: &Path) -> Result<NoiseRules, NoiseError> {
        let text = std::fs::read_to_string(path).map_err(|e| NoiseError::Io(path.display().to_string(), e))?;
        Ok(toml::from_str(&text)?)
    }

    pub fn save(&self, path: &Path) -> Result<(), NoiseError> {
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text).map_err(|e| NoiseError::Io(path.display().to_string(), e))
    }

    pub fn classify(&self, g: &EventGroup) -> Disposition {
        let hit = self.rules.iter().find(|r| {
            r.provider.eq_ignore_ascii_case(&g.key.provider)
                && r.event_id == g.key.event_id
                && match (&r.payload_key, &r.payload_contains) {
                    (Some(k), Some(want)) => {
                        g.payload_variants.iter().any(|p| p.get(k).is_some_and(|v| v.contains(want.as_str())))
                    }
                    _ => true,
                }
        });
        match hit {
            Some(r) => Disposition::Suppressed { rule: r.name.clone() },
            None => Disposition::Surfaced,
        }
    }
}

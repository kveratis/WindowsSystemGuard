//! Recorder configuration, read only from a file that unprivileged users cannot change.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID,
};

/// SYSTEM, built-in Administrators and TrustedInstaller may own or write the file.
const TRUSTED_SIDS: [&str; 3] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];
/// FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL
const WRITE_MASK: u32 = 0x2 | 0x4 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x4000_0000 | 0x1000_0000;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("{0} is writable by an untrusted account ({1}); refusing to use it")]
    Untrusted(PathBuf, String),
    #[error("cannot inspect permissions of {0}: Win32 error {1}")]
    Acl(PathBuf, u32),
    #[error("invalid config: {0}")]
    Parse(#[from] toml::de::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_interval_ms")]
    pub interval_ms: u64,
}

fn default_interval_ms() -> u64 {
    1000
}

impl Default for Config {
    fn default() -> Self {
        Config { interval_ms: default_interval_ms() }
    }
}

pub fn default_path() -> PathBuf {
    PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into()))
        .join("WindowsSystemGuard")
        .join("config.toml")
}

/// Loads the config after checking that only trusted accounts own or can write the file.
// shortcut: the parent directory's ACL is not checked, so an untrusted account that can rename
// the file's directory entry is not caught; check it when the installer owns the directory.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    check_acl(path)?;
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(path.into(), e))?;
    Ok(toml::from_str(&text)?)
}

fn sid_string(sid: PSID) -> String {
    let mut p: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` points into a live security descriptor; `p` is freed below.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut p) == 0 {
            return "?".into();
        }
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
        LocalFree(p.cast());
        s
    }
}

/// Why an ACE makes the file untrusted, if it does. Only plain allow ACEs are understood;
/// every other access-granting type (compound 4, object 5, callback 9 and 11) can grant write
/// in ways this check does not evaluate, so it is rejected. Deny, audit and label ACEs are ignored.
fn ace_violation(ace_type: u8, mask: u32, sid: &str) -> Option<String> {
    match ace_type {
        0 if mask & WRITE_MASK != 0 && !TRUSTED_SIDS.contains(&sid) => Some(format!("{sid} can write")),
        4 | 5 | 9 | 11 => Some(format!("unsupported access-granting ACE type {ace_type}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditional_and_object_allow_aces_are_rejected() {
        for ty in [4, 5, 9, 11] {
            assert!(ace_violation(ty, 0, "S-1-1-0").is_some(), "type {ty}");
        }
    }

    #[test]
    fn plain_allow_checks_mask_and_sid() {
        assert!(ace_violation(0, 0x2, "S-1-1-0").is_some(), "Everyone write");
        assert!(ace_violation(0, 0x2, "S-1-5-18").is_none(), "SYSTEM write");
        assert!(ace_violation(0, 0x1_20089, "S-1-1-0").is_none(), "Everyone read only");
        assert!(ace_violation(1, 0x2, "S-1-1-0").is_none(), "deny ACE");
    }
}

fn check_acl(path: &Path) -> Result<(), ConfigError> {
    let wide: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(path.as_os_str()).chain([0]).collect();
    let (mut owner, mut dacl): (PSID, *mut ACL) = (std::ptr::null_mut(), std::ptr::null_mut());
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: out-pointers are valid; `sd` owns the memory `owner` and `dacl` point into and is
    // freed on every exit below.
    unsafe {
        let rc = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        );
        if rc != ERROR_SUCCESS {
            return Err(ConfigError::Acl(path.into(), rc));
        }
        let verdict = (|| {
            let o = sid_string(owner);
            if !TRUSTED_SIDS.contains(&o.as_str()) {
                return Some(format!("owner {o}"));
            }
            if dacl.is_null() {
                return Some("no DACL, everyone has access".to_string());
            }
            for i in 0..(*dacl).AceCount as u32 {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                if GetAce(dacl, i, &mut ace) == 0 {
                    return Some("unreadable ACE".to_string());
                }
                let ty = (*(ace as *const ACE_HEADER)).AceType;
                let (mask, sid) = if ty == 0 {
                    let a = ace as *const ACCESS_ALLOWED_ACE;
                    ((*a).Mask, sid_string(std::ptr::addr_of!((*a).SidStart) as PSID))
                } else {
                    (0, String::new())
                };
                if let Some(why) = ace_violation(ty, mask, &sid) {
                    return Some(why);
                }
            }
            None
        })();
        LocalFree(sd);
        match verdict {
            Some(why) => Err(ConfigError::Untrusted(path.into(), why)),
            None => Ok(()),
        }
    }
}

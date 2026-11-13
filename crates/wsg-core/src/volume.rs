//! Volume identification by GUID, so a drive is found regardless of its letter.

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_MORE_DATA};
use windows_sys::Win32::Storage::FileSystem::{
    GetVolumeNameForVolumeMountPointW, GetVolumePathNameW, GetVolumePathNamesForVolumeNameW,
};

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn until_nul(buf: &[u16]) -> &[u16] {
    &buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())]
}

/// First mount path of the volume `{guid}` (braces optional), or `None` if it is not mounted.
pub fn resolve_volume_path(volume_guid: &str) -> Option<PathBuf> {
    let guid = volume_guid.strip_prefix('{').unwrap_or(volume_guid);
    let guid = guid.strip_suffix('}').unwrap_or(guid);
    let shape_ok = guid.len() == 36
        && guid.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
    if !shape_ok {
        return None;
    }
    let name = wide(format!(r"\\?\Volume{{{guid}}}\").as_ref());
    let mut buf = vec![0u16; 1024];
    loop {
        let mut needed = 0u32;
        // SAFETY: `name` is NUL-terminated and `buf` holds `buf.len()` u16s.
        let ok = unsafe {
            GetVolumePathNamesForVolumeNameW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32, &mut needed)
        };
        if ok != 0 {
            break;
        }
        // SAFETY: plain thread-local error read.
        if unsafe { GetLastError() } != ERROR_MORE_DATA {
            return None;
        }
        buf.resize(needed as usize, 0);
    }
    let first = until_nul(&buf);
    (!first.is_empty()).then(|| PathBuf::from(OsString::from_wide(first)))
}

/// GUID (with braces) of the volume holding `path`, or `None`.
pub fn volume_guid_for(path: &Path) -> Option<String> {
    let file = wide(path.as_os_str());
    let mut mount = vec![0u16; file.len().max(261)];
    // SAFETY: `file` is NUL-terminated and `mount` holds `mount.len()` u16s.
    if unsafe { GetVolumePathNameW(file.as_ptr(), mount.as_mut_ptr(), mount.len() as u32) } == 0 {
        return None;
    }
    let mut name = [0u16; 64];
    // SAFETY: `mount` is NUL-terminated by the call above and `name` holds 64 u16s.
    if unsafe { GetVolumeNameForVolumeMountPointW(mount.as_ptr(), name.as_mut_ptr(), name.len() as u32) } == 0 {
        return None;
    }
    let name = String::from_utf16_lossy(until_nul(&name)); // \\?\Volume{guid}\
    let (start, end) = (name.find('{')?, name.rfind('}')?);
    Some(name[start..=end].to_string())
}

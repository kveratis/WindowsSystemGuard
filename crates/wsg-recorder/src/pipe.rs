//! Read-only status pipe: a client sends `STATUS` and gets one JSON line back. Nothing a client
//! sends can change recorder state. The pipe is reachable only by SYSTEM, Administrators and
//! the account the recorder runs as.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::IO::CancelIoEx;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub const PIPE_NAME: &str = r"\\.\pipe\wsg-recorder";
const MAX_INSTANCES: u32 = 8;
/// A client must send its command within this long or it is cut off.
const CLIENT_DEADLINE: Duration = Duration::from_secs(2);

pub struct PipeServer {
    name: String,
    stop: Arc<AtomicBool>,
    accept: Option<std::thread::JoinHandle<()>>,
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // The accept loop is blocked in ConnectNamedPipe; a throwaway client wakes it.
        let w = wide(&self.name);
        // SAFETY: `w` is a NUL-terminated wide string that outlives the call.
        unsafe {
            let h = CreateFileW(w.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut());
            if h != INVALID_HANDLE_VALUE {
                CloseHandle(h);
            }
        }
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// The account this process runs as, as a SID string.
fn current_user_sid() -> Option<String> {
    // SAFETY: the token handle and the buffer are valid for the calls and the handle is closed.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut need = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut need);
        let mut buf = vec![0u8; need as usize];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), need, &mut need);
        CloseHandle(token);
        (ok != 0).then(|| crate::config::sid_string((*(buf.as_ptr() as *const TOKEN_USER)).User.Sid))
    }
}

/// SYSTEM and Administrators, plus the account the recorder runs as.
fn sddl() -> String {
    let mut s = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    if let Some(sid) = current_user_sid().filter(|s| s != "S-1-5-18") {
        s.push_str(&format!("(A;;GRGW;;;{sid})"));
    }
    s
}

/// Starts serving `status` (the current status JSON) on `name`. Fails if another process
/// already owns the pipe name, so the pipe cannot be squatted.
pub fn serve(name: &str, status: Arc<Mutex<String>>) -> io::Result<PipeServer> {
    let sd = wide(&sddl());
    let mut psd = std::ptr::null_mut();
    // SAFETY: `sd` is a NUL-terminated wide string; `psd` receives a LocalAlloc'd descriptor.
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sd.as_ptr(), SDDL_REVISION_1, &mut psd, std::ptr::null_mut()) } == 0 {
        return Err(io::Error::other(format!("security descriptor: {}", io::Error::last_os_error())));
    }
    let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: psd, bInheritHandle: 0 };
    let first = create_instance(name, &sa, true);
    let first = match first {
        Ok(h) => h,
        Err(e) => {
            // SAFETY: `psd` came from the conversion above.
            unsafe { LocalFree(psd) };
            return Err(e);
        }
    };
    // Both instances exist before `serve` returns, so a client that connects at once is never refused.
    let ahead = match create_instance(name, &sa, false) {
        Ok(h) => h,
        Err(e) => {
            // SAFETY: nothing else uses these yet.
            unsafe {
                CloseHandle(first);
                LocalFree(psd);
            }
            return Err(e);
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let (n, s2, first, ahead, psd) = (name.to_string(), stop.clone(), first as usize, ahead as usize, psd as usize);
    let accept = std::thread::spawn(move || {
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd as *mut _,
            bInheritHandle: 0,
        };
        // Keep one instance listening ahead of the one being served, so a client that arrives
        // while another is being handled finds a free instance instead of "all busy".
        let next = |stop: &AtomicBool| loop {
            match create_instance(&n, &sa, false) {
                Ok(h) => break Some(h),
                Err(_) if stop.load(Ordering::SeqCst) => break None,
                // All instances busy: wait for a client to finish.
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        };
        let mut h = first as HANDLE;
        let mut ahead = Some(ahead as HANDLE);
        loop {
            // SAFETY: `h` is a pipe instance this thread owns.
            let connected = unsafe {
                ConnectNamedPipe(h, std::ptr::null_mut()) != 0
                    || io::Error::last_os_error().raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32)
            };
            if s2.load(Ordering::SeqCst) || ahead.is_none() {
                // SAFETY: this thread owns both instances.
                unsafe {
                    CloseHandle(h);
                    if let Some(a) = ahead {
                        CloseHandle(a);
                    }
                }
                break;
            }
            if connected {
                let (status, client) = (status.clone(), h as usize);
                std::thread::spawn(move || serve_client(client as HANDLE, &status));
            } else {
                // SAFETY: the failed connection's handle is ours to close.
                unsafe { CloseHandle(h) };
            }
            h = ahead.take().unwrap();
            ahead = next(&s2);
        }
        // SAFETY: `psd` is no longer used after this thread ends.
        unsafe { LocalFree(psd as *mut _) };
    });
    Ok(PipeServer { name: name.to_string(), stop, accept: Some(accept) })
}

fn create_instance(name: &str, sa: &SECURITY_ATTRIBUTES, first: bool) -> io::Result<HANDLE> {
    let w = wide(name);
    let open = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
    // SAFETY: `w` and `sa` are valid for the call.
    let h = unsafe {
        CreateNamedPipeW(
            w.as_ptr(),
            open,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            MAX_INSTANCES,
            64 << 10,
            256,
            0,
            sa,
        )
    };
    if h == INVALID_HANDLE_VALUE {
        Err(io::Error::other(format!("CreateNamedPipeW {name}: {}", io::Error::last_os_error())))
    } else {
        Ok(h)
    }
}

/// Reads one command and answers it. A client that sends nothing is cut off after
/// `CLIENT_DEADLINE` by cancelling its pending read.
fn serve_client(h: HANDLE, status: &Mutex<String>) {
    let open = Arc::new(Mutex::new(true));
    let (hh, o) = (h as usize, open.clone());
    std::thread::spawn(move || {
        std::thread::sleep(CLIENT_DEADLINE);
        // The lock makes "still open" and the cancel one step; the server closes under it too.
        if *o.lock().unwrap() {
            // SAFETY: the handle is still open (checked under the lock).
            unsafe { CancelIoEx(hh as HANDLE, std::ptr::null()) };
        }
    });
    let mut buf = [0u8; 64];
    let mut n = 0u32;
    // SAFETY: `buf` and `n` are valid for the call.
    let read = unsafe { ReadFile(h, buf.as_mut_ptr().cast(), buf.len() as u32, &mut n, std::ptr::null_mut()) };
    let reply = if read != 0 && buf[..n as usize].trim_ascii() == b"STATUS" {
        let mut s = status.lock().unwrap().clone();
        s.push('\n');
        s
    } else {
        "ERR\n".to_string()
    };
    if read != 0 {
        let mut w = 0u32;
        // SAFETY: the reply buffer is valid for the call.
        unsafe {
            WriteFile(h, reply.as_ptr().cast(), reply.len() as u32, &mut w, std::ptr::null_mut());
            FlushFileBuffers(h);
        }
    }
    let mut g = open.lock().unwrap();
    *g = false;
    // SAFETY: closed once, under the lock that stops the watchdog from touching it.
    unsafe {
        DisconnectNamedPipe(h);
        CloseHandle(h);
    }
}

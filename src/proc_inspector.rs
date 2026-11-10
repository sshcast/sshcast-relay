use sshcast_proto::v1::{ProcessAncestor, ProcessContext};
use std::path::Path;
use tokio::net::UnixStream;

pub const MAX_ANCESTOR_DEPTH: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

/// Extracts `SO_PEERCRED` (`uid`, `gid`, `pid`) from an accepted Unix domain socket connection
/// and verifies that the caller's `uid` matches `expected_uid`.
pub fn verify_peer_cred(stream: &UnixStream, expected_uid: u32) -> Result<PeerCred, String> {
    let cred = stream
        .peer_cred()
        .map_err(|e| format!("failed to read SO_PEERCRED: {e}"))?;
    let uid = cred.uid();
    let gid = cred.gid();
    let pid = cred.pid().unwrap_or(0) as u32;

    if uid != expected_uid {
        return Err(format!(
            "UID mismatch on Unix socket: caller uid={uid}, relay uid={expected_uid}"
        ));
    }

    Ok(PeerCred { uid, gid, pid })
}

/// Inspects `/proc/<pid>` and walks up to `MAX_ANCESTOR_DEPTH` (6) parent levels to build a `ProcessContext`.
pub fn inspect_process_context(hostname: &str, uid: u32, pid: u32) -> ProcessContext {
    inspect_process_context_in_proc(Path::new("/proc"), hostname, uid, pid)
}

/// Inspects `<proc_root>/<pid>` (injectable `/proc` root for unit testing) and walks up to 6 parent levels.
pub fn inspect_process_context_in_proc(
    proc_root: &Path,
    hostname: &str,
    uid: u32,
    pid: u32,
) -> ProcessContext {
    if pid == 0 {
        return ProcessContext {
            hostname: hostname.to_string(),
            uid,
            pid: 0,
            comm: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            ancestors: Vec::new(),
        };
    }

    let direct = read_proc_entry(proc_root, pid);
    let cwd = std::fs::read_link(proc_root.join(pid.to_string()).join("cwd"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut ancestors = Vec::with_capacity(MAX_ANCESTOR_DEPTH);
    let mut curr_ppid = direct.ppid;

    for _ in 0..MAX_ANCESTOR_DEPTH {
        if curr_ppid <= 1 {
            break;
        }
        let anc = read_proc_entry(proc_root, curr_ppid);
        if anc.comm.is_empty() && anc.cmdline.is_empty() {
            break;
        }
        let next_ppid = anc.ppid;
        ancestors.push(ProcessAncestor {
            pid: curr_ppid,
            comm: anc.comm,
            cmdline: anc.cmdline,
        });
        if next_ppid == curr_ppid {
            break;
        }
        curr_ppid = next_ppid;
    }

    ProcessContext {
        hostname: hostname.to_string(),
        uid,
        pid,
        comm: direct.comm,
        cmdline: direct.cmdline,
        cwd,
        ancestors,
    }
}

#[derive(Default)]
struct ProcEntry {
    comm: String,
    cmdline: String,
    ppid: u32,
}

fn read_proc_entry(proc_root: &Path, pid: u32) -> ProcEntry {
    let dir = proc_root.join(pid.to_string());
    let mut entry = ProcEntry::default();

    if let Ok(stat_raw) = std::fs::read_to_string(dir.join("stat")) {
        if let Some((comm, ppid)) = parse_proc_stat(&stat_raw) {
            entry.comm = comm;
            entry.ppid = ppid;
        }
    }

    if let Ok(comm_raw) = std::fs::read_to_string(dir.join("comm")) {
        let trimmed = comm_raw.trim_end_matches(&['\r', '\n'][..]);
        if !trimmed.is_empty() {
            entry.comm = trimmed.to_string();
        }
    }

    if let Ok(cmd_bytes) = std::fs::read(dir.join("cmdline")) {
        entry.cmdline = format_cmdline(&cmd_bytes);
    }

    if entry.cmdline.is_empty() && !entry.comm.is_empty() {
        entry.cmdline = entry.comm.clone();
    }

    entry
}

/// Parses `/proc/<pid>/stat` safely even when `comm` contains spaces or parentheses.
/// Format: `pid (comm) state ppid ...`
pub fn parse_proc_stat(stat_line: &str) -> Option<(String, u32)> {
    let open = stat_line.find('(')?;
    let close = stat_line.rfind(')')?;
    if close <= open {
        return None;
    }
    let comm = stat_line[open + 1..close].to_string();
    let rest = stat_line.get(close + 1..)?.trim_start();
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    let ppid_str = fields.next()?;
    let ppid = ppid_str.parse::<u32>().ok()?;
    Some((comm, ppid))
}

/// Converts a NUL-separated `/proc/<pid>/cmdline` byte buffer into a human-readable command string.
pub fn format_cmdline(bytes: &[u8]) -> String {
    let mut bytes = bytes;
    while bytes.last() == Some(&0) {
        bytes = &bytes[..bytes.len() - 1];
    }
    if bytes.is_empty() {
        return String::new();
    }
    bytes
        .split(|&b| b == 0)
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

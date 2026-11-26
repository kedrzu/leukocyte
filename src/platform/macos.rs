//! macOS implementation: `libproc` for the per-pid kernel tables, `sysctl` for `kinfo_proc` and
//! `KERN_PROCARGS2`.
//!
//! Every per-process read that happens after the snapshot takes a [`ProcKey`] and checks the
//! pid's start time once the read is done: if the pid now belongs to another process, the result
//! is discarded. A start time cannot repeat, so a match after the read proves the read saw the
//! right process.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use libc::c_int;
use libproc::libproc::bsd_info::BSDInfo;
use libproc::libproc::file_info::{ListFDs, ProcFDType, pidfdinfo};
use libproc::libproc::kinfo::KinfoProc;
use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind, TcpSIState};
use libproc::libproc::pid_rusage::{RUsageInfoV2, pidrusage};
use libproc::libproc::proc_pid::{kproc_info_raw, listpidinfo, pidinfo};
use libproc::libproc::task_info::TaskAllInfo;
use libproc::processes::{ProcFilter, pids_by_type};

use super::{BaseInfo, Cmdline, ProcKey, Sockets, Usage};

/// The kernel's "no device" value of `e_tdev`: the process has no controlling terminal.
const NODEV: u32 = u32::MAX;

/// Every pid on the system, including pid 0 (the kernel) and other users' processes.
pub fn list_pids() -> io::Result<Vec<i32>> {
    Ok(pids_by_type(ProcFilter::All)?
        .into_iter()
        .filter_map(|pid| i32::try_from(pid).ok())
        .collect())
}

/// The eagerly read facts of `pid`, or `None` when the pid no longer exists.
///
/// The user's own processes come from `PROC_PIDTASKALLINFO`. The kernel refuses that for another
/// uid, so those fall back to `sysctl(KERN_PROC_PID)`, which carries identity, parentage and
/// the terminal but no resource counters: `rss` and `usage` stay `None`.
pub fn base_info(pid: i32) -> Option<BaseInfo> {
    if let Ok(all) = pidinfo::<TaskAllInfo>(pid, 0) {
        let bsd = &all.pbsd;
        return Some(BaseInfo {
            key: ProcKey {
                pid,
                start: micros(bsd.pbi_start_tvsec, bsd.pbi_start_tvusec)?,
            },
            ppid: i32::try_from(bsd.pbi_ppid).ok()?,
            uid: bsd.pbi_uid,
            tty: (bsd.e_tdev != NODEV).then_some(bsd.e_tdev),
            session: session(pid),
            rss: Some(all.ptinfo.pti_resident_size),
            usage: usage(pid),
        });
    }
    let kinfo = kproc_info_raw(pid).ok()?;
    if kinfo.kp_proc.p_pid != pid {
        return None;
    }
    let eproc = &kinfo.kp_eproc;
    Some(BaseInfo {
        key: ProcKey {
            pid,
            start: kinfo_start(pid)?,
        },
        ppid: eproc.e_ppid,
        uid: eproc.e_ucred.cr_uid,
        // `e_tdev` is a signed `dev_t` here; NODEV is -1.
        tty: u32::try_from(eproc.e_tdev).ok(),
        session: session(pid),
        rss: None,
        usage: usage(pid),
    })
}

/// The executable, argv and the allowed part of the environment of `key`, parsed from
/// `sysctl(KERN_PROCARGS2)`. Only variables named in `env_allow` are kept; the rest are skipped
/// during parsing and the raw buffer is dropped here.
pub fn cmdline(key: ProcKey, env_allow: &BTreeSet<String>) -> Option<Cmdline> {
    let mut buf = vec![0u8; arg_max()?];
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, key.pid];
    let mut len = buf.len();
    // SAFETY: `mib` holds `mib.len()` valid ints; `buf` is writable for `len` bytes, the kernel
    // writes at most `len` bytes into it and stores the written length back into `len`; no new
    // value is set (null pointer, length 0).
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len().try_into().ok()?,
            buf.as_mut_ptr().cast(),
            &raw mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let parsed = parse_procargs2(buf.get(..len)?, env_allow);
    still_same(key).then_some(parsed).flatten()
}

/// The current working directory of `key` (`PROC_PIDVNODEPATHINFO`).
pub fn cwd(key: ProcKey) -> Option<PathBuf> {
    // SAFETY: `proc_vnodepathinfo` is plain old data (integers and byte arrays); all-zero is a
    // valid value.
    let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
    let size = c_int::try_from(size_of::<libc::proc_vnodepathinfo>()).ok()?;
    // SAFETY: `info` is a writable `proc_vnodepathinfo` of exactly `size` bytes, the layout the
    // kernel writes for this flavor.
    let written = unsafe {
        libc::proc_pidinfo(
            key.pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            (&raw mut info).cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    let path: Vec<u8> = info
        .pvi_cdir
        .vip_path
        .as_flattened()
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c.cast_unsigned())
        .collect();
    if path.is_empty() || !still_same(key) {
        return None;
    }
    Some(PathBuf::from(OsString::from_vec(path)))
}

/// The TCP sockets `key` holds: listening ports and established connections.
pub fn sockets(key: ProcKey) -> Option<Sockets> {
    let bsd = pidinfo::<BSDInfo>(key.pid, 0).ok()?;
    if micros(bsd.pbi_start_tvsec, bsd.pbi_start_tvusec)? != key.start {
        return None;
    }
    let slots = usize::try_from(bsd.pbi_nfiles).ok()?;
    let fds = if slots == 0 {
        Vec::new()
    } else {
        listpidinfo::<ListFDs>(key.pid, slots).ok()?
    };
    let mut sockets = Sockets::default();
    let mut established_ports = Vec::new();
    for fd in fds {
        if !matches!(ProcFDType::from(fd.proc_fdtype), ProcFDType::Socket) {
            continue;
        }
        // The process may close the descriptor between the listing and this read; a closed
        // descriptor holds no connection, so skipping it is accurate.
        let Ok(info) = pidfdinfo::<SocketFDInfo>(key.pid, fd.proc_fd) else {
            continue;
        };
        if !matches!(SocketInfoKind::from(info.psi.soi_kind), SocketInfoKind::Tcp) {
            continue;
        }
        // SAFETY: `soi_kind == SOCKINFO_TCP` means the kernel filled the `pri_tcp` member of the
        // union.
        let tcp = unsafe { info.psi.soi_proto.pri_tcp };
        let Some(port) = local_port(tcp.tcpsi_ini.insi_lport) else {
            continue;
        };
        match TcpSIState::from(tcp.tcpsi_state) {
            TcpSIState::Listen => {
                sockets.listening.insert(port);
            }
            TcpSIState::Established => established_ports.push(port),
            _ => {}
        }
    }
    sockets.established = established_ports.len();
    sockets.inbound = established_ports
        .iter()
        .filter(|port| sockets.listening.contains(port))
        .count();
    still_same(key).then_some(sockets)
}

unsafe extern "C" {
    /// `<malloc/malloc.h>`: releases free memory of `zone` (all zones when null) back to the
    /// system, up to `goal` bytes (as much as possible when 0); returns the bytes released.
    fn malloc_zone_pressure_relief(
        zone: *mut libc::malloc_zone_t,
        goal: libc::size_t,
    ) -> libc::size_t;
}

/// Returns the allocator's free pages to the system, as it does on its own only under memory
/// pressure. A scan allocates and frees a table of every process; without this, the freed
/// pages stay dirty and count against the daemon's footprint until the next scan reuses them.
pub fn release_free_memory() {
    // SAFETY: a null zone asks for every zone and 0 for as much as possible; the call only
    // returns free pages, which no live allocation uses, to the system.
    unsafe {
        malloc_zone_pressure_relief(std::ptr::null_mut(), 0);
    }
}

/// The daemon's own pid.
pub fn current_pid() -> i32 {
    // SAFETY: `getpid` takes no arguments, touches no memory and cannot fail.
    unsafe { libc::getpid() }
}

/// The daemon's effective uid.
pub fn current_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
    unsafe { libc::geteuid() }
}

/// Sends `sig` to `key` if the pid still belongs to that process, re-checking the start time
/// immediately before `kill(2)`.
///
/// Returns `Ok(true)` when the signal was sent, `Ok(false)` when the process is gone or the pid
/// now belongs to another process, and an error when the kernel refused the signal.
pub fn signal(key: ProcKey, sig: c_int) -> io::Result<bool> {
    if !still_same(key) {
        return Ok(false);
    }
    // SAFETY: `kill` takes plain integers and touches no memory of ours.
    if unsafe { libc::kill(key.pid, sig) } == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        Ok(false)
    } else {
        Err(err)
    }
}

/// Parses a `KERN_PROCARGS2` buffer: `int argc`, the exec path, NUL padding, `argc` argv
/// strings, then environment strings up to an empty string (the "apple" strings follow).
///
/// Environment entries are matched by name against `env_allow` in place; only allowed entries
/// are copied out. Returns `None` for a malformed or truncated argv.
fn parse_procargs2(buf: &[u8], env_allow: &BTreeSet<String>) -> Option<Cmdline> {
    let argc = usize::try_from(c_int::from_ne_bytes(buf.get(..4)?.try_into().ok()?)).ok()?;
    let (exe, mut rest) = next_cstr(buf.get(4..)?)?;
    let padding = rest.iter().take_while(|&&b| b == 0).count();
    rest = rest.get(padding..)?;

    let mut argv = Vec::with_capacity(argc);
    for _ in 0..argc {
        let (arg, tail) = next_cstr(rest)?;
        argv.push(String::from_utf8_lossy(arg).into_owned());
        rest = tail;
    }

    Some(Cmdline {
        exe: String::from_utf8_lossy(exe).into_owned(),
        argv,
        env: parse_env(rest, env_allow),
    })
}

/// Parses the environment part of a `KERN_PROCARGS2` buffer, keeping only allowed names.
///
/// The kernel withholds the environment of platform binaries (`/bin/sh`, `/bin/zsh`,
/// `/bin/sleep`, system daemons): their buffer ends right after argv, with no terminating empty
/// string (observed 2026-11-26 on this machine). That, like a buffer truncated mid-environment,
/// is `None`; a process started with an empty environment still has the terminator and is
/// `Some` of an empty map.
fn parse_env(mut rest: &[u8], env_allow: &BTreeSet<String>) -> Option<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    loop {
        let (entry, tail) = next_cstr(rest)?;
        if entry.is_empty() {
            return Some(env);
        }
        rest = tail;
        let Some(eq) = entry.iter().position(|&b| b == b'=') else {
            continue;
        };
        let Ok(name) = std::str::from_utf8(&entry[..eq]) else {
            continue;
        };
        if env_allow.contains(name) {
            let value = String::from_utf8_lossy(&entry[eq + 1..]).into_owned();
            env.insert(name.to_owned(), value);
        }
    }
}

/// Splits off the NUL-terminated string at the start of `buf`; `None` when there is no NUL.
fn next_cstr(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = buf.iter().position(|&b| b == 0)?;
    Some((&buf[..end], &buf[end + 1..]))
}

/// The size of the buffer `KERN_PROCARGS2` may fill (`KERN_ARGMAX`).
fn arg_max() -> Option<usize> {
    static ARG_MAX: OnceLock<Option<usize>> = OnceLock::new();
    *ARG_MAX.get_or_init(|| {
        let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
        let mut value: c_int = 0;
        let mut len = size_of::<c_int>();
        // SAFETY: `mib` holds `mib.len()` valid ints; `value` is a writable `c_int` and `len` is
        // its size; no new value is set.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len().try_into().ok()?,
                (&raw mut value).cast(),
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        (rc == 0).then(|| usize::try_from(value).ok()).flatten()
    })
}

/// Whether `key` is still running: the pid belongs to that process and it is not a zombie (a
/// process that exited and waits for its parent to reap it).
pub fn alive(key: ProcKey) -> bool {
    let Some(kinfo) = kinfo(key.pid) else {
        return false;
    };
    let zombie = u32::try_from(kinfo.kp_proc.p_stat).ok() == Some(libc::SZOMB);
    !zombie && kinfo_start_of(&kinfo) == Some(key.start)
}

/// Whether `key.pid` still belongs to the process that started at `key.start`.
fn still_same(key: ProcKey) -> bool {
    kinfo_start(key.pid) == Some(key.start)
}

/// `sysctl(KERN_PROC_PID)` of `pid`, readable for every uid.
fn kinfo(pid: i32) -> Option<KinfoProc> {
    let kinfo = kproc_info_raw(pid).ok()?;
    (kinfo.kp_proc.p_pid == pid).then_some(kinfo)
}

/// The start time of `pid` from `sysctl(KERN_PROC_PID)`, readable for every uid.
fn kinfo_start(pid: i32) -> Option<u64> {
    kinfo_start_of(&kinfo(pid)?)
}

fn kinfo_start_of(kinfo: &KinfoProc) -> Option<u64> {
    // `p_un` is the `p_starttime` member of the kernel's union.
    let start = kinfo.kp_proc.p_un;
    micros(
        u64::try_from(start.tv_sec).ok()?,
        u64::try_from(start.tv_usec).ok()?,
    )
}

fn micros(sec: u64, usec: u64) -> Option<u64> {
    sec.checked_mul(1_000_000)?.checked_add(usec)
}

fn session(pid: i32) -> Option<i32> {
    // SAFETY: `getsid` takes a plain integer and touches no memory of ours.
    let sid = unsafe { libc::getsid(pid) };
    (sid >= 0).then_some(sid)
}

fn usage(pid: i32) -> Option<Usage> {
    let ru = pidrusage::<RUsageInfoV2>(pid).ok()?;
    Some(Usage {
        cpu: ticks(ru.ri_user_time.checked_add(ru.ri_system_time)?)?,
        children_cpu: ticks(ru.ri_child_user_time.checked_add(ru.ri_child_system_time)?)?,
        disk_read: ru.ri_diskio_bytesread,
        disk_written: ru.ri_diskio_byteswritten,
    })
}

/// Converts Mach absolute time units to a duration. `proc_pid_rusage` reports CPU time in these
/// units, not nanoseconds: on Apple Silicon one unit is 125/3 ns (measured 2026-11-26 against
/// `getrusage` on this machine).
fn ticks(units: u64) -> Option<Duration> {
    static TIMEBASE: OnceLock<Option<(u32, u32)>> = OnceLock::new();
    let (numer, denom) = (*TIMEBASE.get_or_init(|| {
        let mut info = mach2::mach_time::mach_timebase_info { numer: 0, denom: 0 };
        // SAFETY: `info` is a writable `mach_timebase_info` the call fills in.
        let rc = unsafe { mach2::mach_time::mach_timebase_info(&raw mut info) };
        (rc == mach2::kern_return::KERN_SUCCESS && info.denom != 0)
            .then_some((info.numer, info.denom))
    }))?;
    let nanos = u128::from(units) * u128::from(numer) / u128::from(denom);
    Some(Duration::from_nanos(u64::try_from(nanos).ok()?))
}

/// A TCP port from the kernel's `insi_lport`: a network-order 16-bit value in an int.
fn local_port(raw: c_int) -> Option<u16> {
    u16::try_from(raw).ok().map(u16::from_be)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn procargs(argc: i32, strings: &[&str]) -> Vec<u8> {
        let mut buf = argc.to_ne_bytes().to_vec();
        for s in strings {
            buf.extend_from_slice(s.as_bytes());
            buf.push(0);
        }
        buf
    }

    fn allow(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    fn env(pairs: &[(&str, &str)]) -> Option<BTreeMap<String, String>> {
        Some(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    }

    /// Privacy: a variable outside the allowlist is never copied out of the buffer.
    #[test]
    fn parse_keeps_only_allowlisted_env_and_never_the_rest() {
        let secret = "s3cr3t-token-value";
        let buf = procargs(
            2,
            &[
                "/bin/sleep",
                "",
                "",
                "sleep",
                "30",
                "KEEP=kept",
                &format!("API_TOKEN={secret}"),
                "PASEO_AGENT_ID=agent-1",
                "",
                "executable_path=/bin/sleep",
            ],
        );
        let parsed = parse_procargs2(&buf, &allow(&["KEEP", "PASEO_AGENT_ID"])).unwrap();

        assert_eq!(parsed.exe, "/bin/sleep");
        assert_eq!(parsed.argv, ["sleep", "30"]);
        assert_eq!(
            parsed.env,
            env(&[("KEEP", "kept"), ("PASEO_AGENT_ID", "agent-1")])
        );
        assert!(!format!("{parsed:?}").contains(secret));
    }

    #[test]
    fn parse_stops_env_at_the_apple_strings() {
        let buf = procargs(1, &["/bin/sh", "sh", "A=1", "", "executable_path=/bin/sh"]);
        let parsed = parse_procargs2(&buf, &allow(&["A", "executable_path"])).unwrap();
        assert_eq!(parsed.env, env(&[("A", "1")]));
    }

    #[test]
    fn parse_skips_env_entries_without_a_value_separator() {
        let buf = procargs(1, &["/bin/sh", "sh", "NOEQUALS", "A=x=y", ""]);
        let parsed = parse_procargs2(&buf, &allow(&["NOEQUALS", "A"])).unwrap();
        assert_eq!(parsed.env, env(&[("A", "x=y")]));
    }

    #[test]
    fn parse_tells_a_withheld_env_from_an_empty_one() {
        // Platform binaries: the buffer ends right after argv.
        let withheld = procargs(2, &["/bin/sleep", "", "/bin/sleep", "30"]);
        let parsed = parse_procargs2(&withheld, &allow(&["A"])).unwrap();
        assert_eq!(parsed.argv, ["/bin/sleep", "30"]);
        assert_eq!(parsed.env, None);

        let empty = procargs(1, &["/bin/x", "x", "", "executable_path=/bin/x"]);
        assert_eq!(
            parse_procargs2(&empty, &allow(&["A"])).unwrap().env,
            env(&[])
        );

        // Truncated in the middle of the environment.
        let mut truncated = procargs(1, &["/bin/x", "x", "A=1"]);
        truncated.extend_from_slice(b"B=2");
        assert_eq!(
            parse_procargs2(&truncated, &allow(&["A"])).unwrap().env,
            None
        );
    }

    #[test]
    fn parse_rejects_malformed_buffers() {
        assert_eq!(parse_procargs2(&[], &allow(&[])), None);
        assert_eq!(parse_procargs2(&[1, 0], &allow(&[])), None);
        // argc says 3, only one argument present.
        assert_eq!(
            parse_procargs2(&procargs(3, &["/bin/sh", "sh"]), &allow(&[])),
            None
        );
        // Negative argc.
        assert_eq!(
            parse_procargs2(&procargs(-1, &["/bin/sh"]), &allow(&[])),
            None
        );
        // Exec path without a terminating NUL.
        let mut buf = 1i32.to_ne_bytes().to_vec();
        buf.extend_from_slice(b"/bin/sh");
        assert_eq!(parse_procargs2(&buf, &allow(&[])), None);
    }

    #[test]
    fn local_port_converts_from_network_order() {
        assert_eq!(local_port(i32::from(8080u16.to_be())), Some(8080));
        assert_eq!(local_port(-1), None);
    }
}

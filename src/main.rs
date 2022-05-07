// SPDX-License-Identifier: ISC

/*
 * Copyright © 2022 rusty-snake
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#![warn(rust_2018_idioms)]
#![deny(missing_debug_implementations)]

use libc::{
    mode_t, pid_t, SYS_execveat, AT_EMPTY_PATH, AT_FDCWD, EACCES, ENAMETOOLONG, EXDEV, O_ACCMODE,
    O_APPEND, O_CLOEXEC, O_CREAT, O_DIRECT, O_DIRECTORY, O_DSYNC, O_EXCL, O_LARGEFILE, O_NDELAY,
    O_NOATIME, O_NOCTTY, O_NOFOLLOW, O_NONBLOCK, O_PATH, O_SYNC, O_TMPFILE, O_TRUNC, WNOHANG,
};
use libseccomp::error::SeccompError;
use libseccomp::{
    notify_id_valid, ScmpAction, ScmpFd, ScmpFilterContext, ScmpNotifReq, ScmpNotifResp,
    ScmpSyscall,
};
use libseccomp_ext_unotify_addfd::ScmpNotifAddfd;
use libseccomp_sys_ext_unotify_addfd::SECCOMP_ADDFD_FLAG_SEND;
use openat2_sys::{open_how, openat2, RESOLVE_IN_ROOT};
use std::error::Error as StdError;
use std::ffi::CStr;
use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::Error as IoError;
use std::mem::size_of;
use std::os::raw::{c_char, c_int};
use std::os::unix::prelude::*;
use std::path::Path;
use std::process::id as getpid;
use std::ptr;
use std::thread;

mod libseccomp_ext_unotify_addfd;
mod libseccomp_sys_ext_unotify_addfd;
mod openat2_sys;

const PATH_MAX: usize = libc::PATH_MAX as usize;
const O_ALL: i32 = O_ACCMODE
    | O_CREAT
    | O_EXCL
    | O_NOCTTY
    | O_TRUNC
    | O_APPEND
    | O_NONBLOCK
    | O_DSYNC
    | O_DIRECT
    | O_LARGEFILE
    | O_DIRECTORY
    | O_NOFOLLOW
    | O_NOATIME
    | O_CLOEXEC
    | O_SYNC
    | O_PATH
    | O_TMPFILE
    | O_NDELAY;

fn main() -> Result<(), Box<dyn StdError>> {
    let (child_pid, unotify_fd) = thread::spawn(|| -> Result<(_, _), SendError> {
        // Open an fd for cat before we load the seccomp filter in order to avoid deadlocking
        // ourself.
        let cat_fd: i32 =
            cvt(unsafe { libc::open("/usr/bin/cat\0".as_ptr().cast(), O_PATH | O_CLOEXEC) })?;

        let unotify_fd = load_seccomp()?;

        match unsafe { libc::fork() } {
            0 => {
                extern "C" {
                    static mut environ: *const *const c_char;
                }

                unsafe {
                    dbg!(libc::openat(
                        AT_FDCWD,
                        "/enoent\0".as_ptr().cast(),
                        O_CLOEXEC,
                    ));
                    dbg!(IoError::last_os_error());
                }

                let empty_path: *const c_char = "\0".as_ptr().cast();
                let argv: *const *const c_char = [
                    "/usr/bin/cat\0".as_ptr().cast(),
                    "/etc/passwd\0".as_ptr().cast(),
                    "/../../cmdline\0".as_ptr().cast(),
                    "./Cargo.toml\0".as_ptr().cast(),
                    ptr::null(),
                ]
                .as_ptr();
                let envp: *const *const c_char = unsafe { environ };
                unsafe {
                    execveat(cat_fd, empty_path, argv, envp, AT_EMPTY_PATH);
                    libc::abort();
                }
            }
            -1 => Err(IoError::last_os_error().into()),
            pid => {
                let _ = unsafe { libc::close(cat_fd) };
                Ok((pid, unotify_fd))
            }
        }
    })
    .join()
    .unwrap()?;

    let our_pid = getpid();
    let snr_openat = ScmpSyscall::from_name("openat")?;
    // FIXME: This actually does not work because we likely block on ScmpNotifReq::receive when the
    // child exits, never get a new request and deadlock.
    while waitpid(child_pid, None, WNOHANG)?.is_none() {
        eprintln!("Waiting for unotify requests ...");
        let req = ScmpNotifReq::receive(unotify_fd)?;

        if req.pid == our_pid {
            panic!("We should never come here.");
        }

        if req.data.syscall != snr_openat {
            unreachable!();
        }

        if let Err(err) = handle_request(req, unotify_fd, || notify_id_valid(unotify_fd, req.id)) {
            eprintln!("Failed to handle request: {err}");
        }
    }

    Ok(())
}

fn handle_request<F>(
    req: ScmpNotifReq,
    unotify_fd: ScmpFd,
    ensure_notify_id_valid: F,
) -> Result<(), Box<dyn StdError>>
where
    F: Fn() -> Result<(), SeccompError>,
{
    let dirfd: i32 = req.data.args[0] as i32;
    let pathname_addr: u64 = req.data.args[1];
    let mut pathname_buf: [u8; PATH_MAX] = [0; PATH_MAX];
    let flags: i32 = req.data.args[2] as i32;
    let mode: mode_t = req.data.args[3] as mode_t;

    let mem = File::open(&format!("/proc/{}/mem", req.pid))?;
    ensure_notify_id_valid()?;

    // TODO: Continue on ErrorKind::Interrupted
    let nread = mem.read_at(&mut pathname_buf, pathname_addr)?;
    ensure_notify_id_valid()?;

    if strnlen(&pathname_buf, nread) == nread {
        if nread == PATH_MAX {
            ScmpNotifResp::new(req.id, 0, -ENAMETOOLONG, 0).respond(unotify_fd)?;
        } else {
            //ScmpNotifResp::new(req.id, 0, -<error>, 0).respond(unotify_fd)?;
            return Err(NotImplementedError.into());
        }
        return Ok(());
    }

    let pathname_cstr = unsafe { CStr::from_ptr(pathname_buf.as_ptr().cast()) };
    let pathname_osstr = OsStr::from_bytes(pathname_cstr.to_bytes());
    let pathname_path = Path::new(pathname_osstr);
    if input(&format!("Allow '{}'? [y/N] ", pathname_path.display()))?.trim() != "y" {
        ScmpNotifResp::new(req.id, 0, -EACCES, 0).respond(unotify_fd)?;
        return Ok(());
    }

    if pathname_buf[0] == b'/' {
        let rootdir_slink = format!("/proc/{}/root\0", req.pid);
        let rootdir_fd: i32 = cvt(unsafe {
            libc::open(
                rootdir_slink.as_ptr().cast(),
                O_PATH | O_CLOEXEC | O_DIRECTORY,
            )
        })?;
        ensure_notify_id_valid()?;

        let mut how = open_how {
            // openat allows unknown flags, openat2 not.
            flags: (flags & O_ALL) as u64,
            mode: if (flags & (O_CREAT | O_TMPFILE)) != 0 {
                mode
            } else {
                0
            } as u64,
            resolve: RESOLVE_IN_ROOT,
        };

        let fd = unsafe {
            openat2(
                rootdir_fd,
                pathname_buf.as_ptr().cast(),
                &mut how,
                size_of::<open_how>(),
            )
        };
        if fd == -1 {
            let errno = match unsafe { *libc::__errno_location() } {
                // Acording to openat2(2) we should retry if EAGAIN is returned.
                // Keep in mind that EAGAIN==EWOULDBLOCK on Linux and EWOULDBLOCK is a possible
                // errno if flags contains O_NONBLOCK
                //EAGAIN => unimplemented!(),
                // EXDEV means violation of RESOLVE_IN_ROOT, let's return EACCES in that case.
                EXDEV => EACCES,
                e => e,
            };
            ScmpNotifResp::new(req.id, 0, -errno, 0).respond(unotify_fd)?;
        } else {
            ScmpNotifAddfd::new(
                req.id,
                SECCOMP_ADDFD_FLAG_SEND,
                fd,                         // srcfd
                None,                       // newfd
                (flags & O_CLOEXEC) as u32, // newfd_flags
            )
            .addfd(unotify_fd)?;
            let _ = unsafe { libc::close(fd) };
        }
        let _ = unsafe { libc::close(rootdir_fd) };
    } else if dirfd == AT_FDCWD {
        // /proc/{pid}/cwd
        return Err(NotImplementedError.into());
    } else {
        // /proc/{pid}/fd/{dirfd} or pidfd_getfd
        return Err(NotImplementedError.into());
    }

    Ok(())
}

fn load_seccomp() -> Result<ScmpFd, SeccompError> {
    let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    ctx.add_rule(
        ScmpAction::Errno(libc::ENOSYS),
        ScmpSyscall::from_name("creat")?,
    )?;
    ctx.add_rule(
        ScmpAction::Errno(libc::ENOSYS),
        ScmpSyscall::from_name("open")?,
    )?;
    ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("openat")?)?;
    ctx.add_rule(
        ScmpAction::Errno(libc::ENOSYS),
        ScmpSyscall::from_name("openat2")?,
    )?;
    ctx.load()?;

    ctx.get_notify_fd()
}

fn input(prompt: &str) -> Result<String, IoError> {
    let mut stdout = io::stdout();
    stdout.write_all(prompt.as_bytes())?;
    stdout.flush()?;

    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;

    Ok(buf)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NotImplementedError;
impl fmt::Display for NotImplementedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Not Implemented")
    }
}
impl StdError for NotImplementedError {}

#[derive(Debug)]
struct SendError(Box<dyn StdError + Send>);
impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl StdError for SendError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&*self.0)
    }
}
/*
impl<E: StdError + Send + 'static> From<E> for SendError {
    fn from(e: E) -> Self {
        Self(Box::new(e))
    }
}
*/
impl From<IoError> for SendError {
    fn from(e: IoError) -> Self {
        Self(Box::new(e))
    }
}
impl From<SeccompError> for SendError {
    fn from(e: SeccompError) -> Self {
        Self(Box::new(e))
    }
}

fn cvt(rv: i32) -> Result<i32, IoError> {
    if rv == -1 {
        Err(IoError::last_os_error())
    } else {
        Ok(rv)
    }
}

fn strnlen(s: &[u8], maxlen: usize) -> usize {
    unsafe { libc::strnlen(s.as_ptr().cast(), maxlen) }
}

fn waitpid(
    pid: pid_t,
    wstatus: Option<&mut c_int>,
    options: c_int,
) -> Result<Option<pid_t>, IoError> {
    match cvt(unsafe { libc::waitpid(pid, wstatus.map_or(ptr::null_mut(), |w| w), options) })? {
        0 => Ok(None),
        pid => Ok(Some(pid)),
    }
}

unsafe fn execveat(
    dirfd: c_int,
    pathname: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
    flags: c_int,
) -> c_int {
    libc::syscall(SYS_execveat, dirfd, pathname, argv, envp, flags) as c_int
}

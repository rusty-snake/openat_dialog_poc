// SPDX-License-Identifier: 0BSD

/*
 * Copyright © 2022 rusty-snake
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

use super::libseccomp_sys_ext_unotify_addfd::*;
use libseccomp::ScmpFd;
use std::io;
use std::os::unix::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScmpNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: RawFd,
    pub newfd: Option<RawFd>,
    pub newfd_flags: u32,
}
impl ScmpNotifAddfd {
    fn to_sys(self) -> seccomp_notif_addfd {
        seccomp_notif_addfd {
            id: self.id,
            flags: self.flags,
            srcfd: self.srcfd as _,
            newfd: self.newfd.unwrap_or(0) as _,
            newfd_flags: self.newfd_flags,
        }
    }

    pub fn new(id: u64, flags: u32, srcfd: RawFd, newfd: Option<RawFd>, newfd_flags: u32) -> Self {
        Self {
            id,
            flags,
            srcfd,
            newfd,
            newfd_flags,
        }
    }

    pub fn addfd(&self, fd: ScmpFd) -> io::Result<()> {
        let mut addfd = self.to_sys();
        if unsafe { seccomp_notify_addfd(fd, &mut addfd) } == -1 {
            Err(io::Error::last_os_error())
            /*
            match unsafe { *libc::__errno_location() } {
                libc::EBADF => unimplemented!("EBADF"),
                libc::EINPROGRESS => unimplemented!("EINPROGRESS"),
                libc::EINVAL => unimplemented!("EINVAL"),
                libc::EMFILE => unimplemented!("EMFILE"),
                libc::ENOENT => unimplemented!("ENOENT"),
                _ => unimplemented!(),
            }
            */
        } else {
            Ok(())
        }
    }
}

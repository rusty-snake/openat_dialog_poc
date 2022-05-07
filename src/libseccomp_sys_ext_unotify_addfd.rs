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

#![allow(dead_code)]

use std::os::raw::{c_int, c_ulong};

pub const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1;
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 2; // since Linux 5.14

/*
#include <linux/seccomp.h>
#include <stdio.h>
#include <sys/ioctl.h>

int main() {
        printf("%li\n", SECCOMP_IOCTL_NOTIF_ADDFD);
}
*/
pub const SECCOMP_IOCTL_NOTIF_ADDFD: c_ulong = 1075323139;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct seccomp_notif_addfd {
    /// The ID of the seccomp notification.
    pub id: u64,
    /// `SECCOMP_ADDFD_FLAG_*`.
    pub flags: u32,
    /// The local fd number.
    pub srcfd: u32,
    /// Optional remote FD number if SETFD option is set, otherwise 0.
    pub newfd: u32,
    /// The `O_*` flags the remote FD should have applied (`libc::O_CLOEXEC`).
    pub newfd_flags: u32,
}

pub unsafe fn seccomp_notify_addfd(fd: c_int, addfd: *mut seccomp_notif_addfd) -> c_int {
    libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ADDFD, addfd)
}

// Copyright © 2015 Geoffroy Couprie
// Copyright © 2015 Andy Grover
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// “Software”), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// Based on code from https://github.com/Geal/rust-syslog.

#![feature(core)]

extern crate libc;
extern crate errno;

use std::intrinsics;
use std::mem;
use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::io::{Error, ErrorKind};
use std::io::Result;
use errno::{Errno, errno};

pub enum SockType {
    Stream,
    Dgram,
    Seqpacket,
}

#[inline]
fn retry<F>(mut f: F) -> libc::c_int where F: FnMut() -> libc::c_int {
    loop {
        let Errno(err) = errno();
        match f() {
            -1 if err == libc::EINTR => {}
            n => return n,
        }
    }
}

fn last_error() -> Error {
    Error::last_os_error()
}

fn addr_to_sockaddr_un(addr: &CString) -> Result<(libc::sockaddr_storage, usize)> {
    // the sun_path length is limited to SUN_LEN (with null)
    assert!(mem::size_of::<libc::sockaddr_storage>() >=
            mem::size_of::<libc::sockaddr_un>());
    let mut storage: libc::sockaddr_storage = unsafe { intrinsics::init() };
    let s: &mut libc::sockaddr_un = unsafe { mem::transmute(&mut storage) };

    let len = addr.as_bytes().len();
    if len > s.sun_path.len() - 1 {
        return Err(Error::new(ErrorKind::InvalidInput,
                              "path must be smaller than SUN_LEN"));
    }
    s.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, value) in s.sun_path.iter_mut().zip(addr.as_bytes().iter()) {
        *slot = *value as i8;
    }

    // count the null terminator
    let len = mem::size_of::<libc::sa_family_t>() + len + 1;
    return Ok((storage, len));
}

fn unix_socket(ty: libc::c_int) -> Result<RawFd> {
    match unsafe { libc::socket(libc::AF_UNIX, ty, 0) } {
        -1 => Err(last_error()),
        fd => Ok(fd)
    }
}

fn connect(addr: &CString, ty: libc::c_int) -> Result<RawFd> {
    let (addr, len) = try!(addr_to_sockaddr_un(addr));
    let fd = try!(unix_socket(ty));
    let addrp = &addr as *const libc::sockaddr_storage;
    match retry(|| unsafe {
        libc::connect(fd, addrp as *const libc::sockaddr,
                      len as libc::socklen_t)
    }) {
        -1 => Err(last_error()),
        _  => Ok(fd)
    }
}

fn bind(addr: &CString, ty: libc::c_int) -> Result<RawFd> {
    let (addr, len) = try!(addr_to_sockaddr_un(addr));
    let fd = try!(unix_socket(ty));
    let addrp = &addr as *const libc::sockaddr_storage;
    match unsafe {
        libc::bind(fd, addrp as *const libc::sockaddr, len as libc::socklen_t)
    } {
        -1 => Err(last_error()),
        _  => Ok(fd)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Unix Datagram
////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct UnixDatagram {
    fd: RawFd,
    connected: bool,
}

impl UnixDatagram {
    pub fn connect(addr: &str, ty: SockType) -> Result<UnixDatagram> {
        let c_ty = match ty {
            SockType::Stream => libc::SOCK_STREAM,
            SockType::Dgram => libc::SOCK_DGRAM,
            SockType::Seqpacket => 5, // FIXME
        };

        let c_addr = try!(CString::new(addr));
        let fd = try!(connect(&c_addr, c_ty));
        Ok(UnixDatagram{
            fd: fd,
            connected: true,
        })
    }

    pub fn bind(addr: &str, ty: SockType) -> Result<UnixDatagram> {
        let c_ty = match ty {
            SockType::Stream => libc::SOCK_STREAM,
            SockType::Dgram => libc::SOCK_DGRAM,
            SockType::Seqpacket => 5, // FIXME
        };

        let c_addr = try!(CString::new(addr));
        bind(&c_addr, c_ty).map(|fd| {
            UnixDatagram {
                fd: fd,
                connected: false,
            }
        })
    }

    fn fd(&self) -> RawFd { self.fd }

    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.connected {
            return Err(Error::new(ErrorKind::InvalidInput,
                                  "must call connect() before calling recv()"));
        }

        let ret = retry(|| unsafe {
            libc::recv(self.fd(),
                       buf.as_ptr() as *mut libc::c_void,
                       buf.len() as libc::size_t,
                       0) as libc::c_int
        });

        if ret < 0 { return Err(last_error()) }

        Ok(ret as usize)
    }

    pub fn recvfrom(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut storage: libc::sockaddr_storage = unsafe { intrinsics::init() };
        let storagep = &mut storage as *mut libc::sockaddr_storage;
        let mut addrlen: libc::socklen_t =
            mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let ret = retry(|| unsafe {
            libc::recvfrom(self.fd(),
                           buf.as_ptr() as *mut libc::c_void,
                           buf.len() as libc::size_t,
                           0,
                           storagep as *mut libc::sockaddr,
                           &mut addrlen) as libc::c_int
        });

        if ret < 0 { return Err(last_error()) }

        Ok(ret as usize)
    }

    pub fn send(&mut self, buf: &[u8]) -> Result<()> {
        if !self.connected {
            return Err(Error::new(ErrorKind::InvalidInput,
                                  "must call connect() before calling send()"));
        }
        let ret = retry(|| unsafe {
            libc::send(self.fd(),
                       buf.as_ptr() as *const libc::c_void,
                       buf.len() as libc::size_t,
                       0) as libc::c_int
        });

        match ret {
            -1 => Err(last_error()),
            n if n as usize != buf.len() => {
                Err(Error::new(ErrorKind::InvalidInput,
                               "couldn't send entire packet at once"))
            }
            _ => Ok(())
        }
    }

    pub fn sendto(&mut self, buf: &[u8], dst: &str) -> Result<()> {
        let c_dst = try!(CString::new(dst));
        let (dst, len) = try!(addr_to_sockaddr_un(&c_dst));
        let dstp = &dst as *const libc::sockaddr_storage;
        let ret = retry(|| unsafe {
            libc::sendto(self.fd(),
                         buf.as_ptr() as *const libc::c_void,
                         buf.len() as libc::size_t,
                         0,
                         dstp as *const libc::sockaddr,
                         len as libc::socklen_t) as libc::c_int
        });

        match ret {
            -1 => Err(last_error()),
            n if n as usize != buf.len() => {
                Err(Error::new(ErrorKind::InvalidInput,
                               "couldn't send entire packet at once"))
            }
            _ => Ok(())
        }
    }
}

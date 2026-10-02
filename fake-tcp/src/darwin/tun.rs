//! `utun` based TUN device implementation for macOS.
//!
//! macOS does not expose a TUN character device like Linux (`/dev/net/tun`).
//! Instead, a userspace program connects a `PF_SYSTEM` / `SYSPROTO_CONTROL`
//! socket to the `com.apple.net.utun_control` kernel control, which creates
//! a `utun<unit>` interface bound to that socket.
//!
//! Notable differences from the Linux TUN implementation:
//!
//! * Every packet read from or written to the control socket is prefixed
//!   with a 4-byte, network byte order address family (`AF_INET` = 2,
//!   `AF_INET6` = 30). The header is consumed by [`Tun::recv`] and
//!   synthesized by [`Tun::send`] / [`Tun::try_send`] using scatter/gather
//!   I/O, so the rest of the crate sees bare IP packets exactly as on Linux.
//! * There is no multi-queue support: one control socket corresponds to
//!   exactly one `utun` interface.
//! * The interface name is always `utun<unit>` and cannot be chosen freely.
//! * Addresses are configured through the `ifconfig` utility, as macOS has
//!   no stable public API for interface address configuration.

use std::ffi::CStr;
use std::io;
use std::mem::{size_of, size_of_val};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::Command;
use std::time::Duration;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// Kernel control name of the utun driver, from `net/if_utun.h`.
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

/// Size of the address family header prepended to every packet.
const AF_HEADER_LEN: usize = 4;

/// Kernel control socket send/receive buffer size. The default is far too
/// small to sustain full throughput without `ENOBUFS` on writes.
const SOCKET_BUFFER_SIZE: libc::c_int = 1024 * 1024;

/// Back-off applied by [`Tun::send`] when the control socket is full.
const SEND_BACKOFF: Duration = Duration::from_micros(500);

/// A TUN device backed by a macOS `utun` kernel control socket.
pub struct Tun {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Tun {
    fn new(
        name: &str,
        local_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
        local_addr6: Option<Ipv6Addr>,
        dst_addr6: Option<Ipv6Addr>,
    ) -> io::Result<Self> {
        let unit = parse_unit(name)?;
        let fd = open_utun(unit)?;
        let name = utun_name(&fd)?;

        configure(&name, local_addr, dst_addr, local_addr6, dst_addr6)?;

        Ok(Self {
            // `EVFILT_WRITE` never fires for kernel control sockets, so only
            // register read interest; see `send` for how writes are handled.
            fd: AsyncFd::with_interest(fd, Interest::READABLE)?,
            name,
        })
    }

    /// Returns the name of the `utun` interface, e.g. `utun5`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Receives an IP packet from the interface into `buf`, stripping the
    /// 4-byte address family header.
    ///
    /// The header is scattered into a stack buffer via `readv`, so the packet
    /// lands directly at `buf[0..]` without an intermediate copy.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut af_hdr = [0u8; AF_HEADER_LEN];
        loop {
            let mut guard = self.fd.readable().await?;
            let res = guard.try_io(|fd| {
                let iov = [
                    libc::iovec {
                        iov_base: af_hdr.as_mut_ptr().cast(),
                        iov_len: af_hdr.len(),
                    },
                    libc::iovec {
                        iov_base: buf.as_mut_ptr().cast(),
                        iov_len: buf.len(),
                    },
                ];
                // SAFETY: both iovecs point to live, writable buffers of the
                // stated lengths for the duration of the call.
                let n = unsafe { libc::readv(fd.as_raw_fd(), iov.as_ptr(), iov.len() as _) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });

            match res {
                Ok(Ok(n)) if n < AF_HEADER_LEN => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "short read from utun",
                    ));
                }
                Ok(Ok(n)) => return Ok(n - AF_HEADER_LEN),
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }

    /// Sends an IP packet to the interface, prepending the address family
    /// header via `writev`.
    ///
    /// Kernel control sockets never report write readiness, so instead of
    /// waiting on the reactor this retries with a short sleep while the
    /// socket buffer is full (`ENOBUFS` / `EAGAIN`).
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            match self.try_send(buf) {
                Err(e) if is_backpressure(&e) => tokio::time::sleep(SEND_BACKOFF).await,
                res => return res,
            }
        }
    }

    /// Attempts to send an IP packet to the interface without waiting.
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        let af: libc::c_int = match buf.first().map(|b| b >> 4) {
            Some(4) => libc::AF_INET,
            Some(6) => libc::AF_INET6,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not an IPv4/IPv6 packet",
                ));
            }
        };
        let af_hdr = (af as u32).to_be_bytes();
        let iov = [
            libc::iovec {
                iov_base: af_hdr.as_ptr() as *mut _,
                iov_len: af_hdr.len(),
            },
            libc::iovec {
                iov_base: buf.as_ptr() as *mut _,
                iov_len: buf.len(),
            },
        ];
        // SAFETY: both iovecs point to live buffers of the stated lengths;
        // `writev` only reads through them.
        let n = unsafe { libc::writev(self.as_raw_fd(), iov.as_ptr(), iov.len() as _) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // utun consumes each write as a single datagram; anything else
        // means the packet was not delivered.
        if n as usize != AF_HEADER_LEN + buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write to utun",
            ));
        }
        Ok(buf.len())
    }
}

fn is_backpressure(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::ENOBUFS)
}

/// Maps an interface name to a kernel control unit: `utunN` → `N + 1`,
/// empty → `0` (kernel picks the next free unit).
fn parse_unit(name: &str) -> io::Result<u32> {
    if name.is_empty() {
        return Ok(0);
    }
    name.strip_prefix("utun")
        .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|d| d.parse::<u32>().ok())
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid tun name {name:?}: macOS requires the form utun<N>"),
            )
        })
}

fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn open_utun(unit: u32) -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2) call; the result is checked before use.
    let raw = cvt(unsafe {
        libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL)
    })?;
    // SAFETY: `raw` is a freshly created descriptor exclusively owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: all-zero is a valid bit pattern for this plain C struct.
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (dst, src) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME) {
        *dst = *src as libc::c_char;
    }
    // SAFETY: CTLIOCGINFO reads/writes exactly one `ctl_info`.
    cvt(unsafe { libc::ioctl(raw, libc::CTLIOCGINFO, &mut info) })?;

    let addr = libc::sockaddr_ctl {
        sc_len: size_of::<libc::sockaddr_ctl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        sc_unit: unit,
        sc_reserved: [0; 5],
    };
    // SAFETY: `addr` is a valid `sockaddr_ctl` of the length passed.
    cvt(unsafe {
        libc::connect(
            raw,
            (&raw const addr).cast(),
            size_of_val(&addr) as libc::socklen_t,
        )
    })?;

    // SAFETY: fcntl/setsockopt on an owned descriptor with valid arguments.
    unsafe {
        cvt(libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC))?;
        let flags = cvt(libc::fcntl(raw, libc::F_GETFL))?;
        // Required by `AsyncFd`: readiness is cached until an operation
        // returns `WouldBlock`, so a blocking fd would stall the runtime.
        cvt(libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK))?;
        let size = SOCKET_BUFFER_SIZE;
        for opt in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
            cvt(libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                opt,
                (&raw const size).cast(),
                size_of_val(&size) as libc::socklen_t,
            ))?;
        }
    }

    Ok(fd)
}

fn utun_name(fd: &OwnedFd) -> io::Result<String> {
    let mut buf = [0u8; libc::IFNAMSIZ];
    let mut len = buf.len() as libc::socklen_t;
    // SAFETY: the kernel writes at most `len` bytes into `buf`.
    cvt(unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    })?;
    CStr::from_bytes_until_nul(&buf)
        .map(|s| s.to_string_lossy().into_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad utun interface name"))
}

fn ifconfig(args: &[&str]) -> io::Result<()> {
    let status = Command::new("/sbin/ifconfig").args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "`ifconfig {}` failed: {status}",
            args.join(" ")
        )))
    }
}

fn configure(
    name: &str,
    local_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    local_addr6: Option<Ipv6Addr>,
    dst_addr6: Option<Ipv6Addr>,
) -> io::Result<()> {
    ifconfig(&[
        name,
        "inet",
        &local_addr.to_string(),
        &dst_addr.to_string(),
        "up",
    ])?;
    if let (Some(local6), Some(dst6)) = (local_addr6, dst_addr6) {
        ifconfig(&[
            name,
            "inet6",
            &local6.to_string(),
            &dst6.to_string(),
            "prefixlen",
            "128",
        ])?;
    }
    Ok(())
}

/// Builder for [`Tun`], mirroring the subset of the `tokio-tun` builder
/// used by the Phantun binaries on Linux. IPv6 addresses are configured here
/// as well since there is no netlink on macOS.
#[derive(Default)]
pub struct TunBuilder {
    name: String,
    address: Option<Ipv4Addr>,
    destination: Option<Ipv4Addr>,
    address6: Option<Ipv6Addr>,
    destination6: Option<Ipv6Addr>,
}

impl TunBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the interface name, which must be of the form `utun<N>`.
    /// If empty, the kernel assigns the next available unit.
    pub fn name(mut self, name: &str) -> Self {
        self.name = name.to_owned();
        self
    }

    /// Sets the local IPv4 address of the interface (the O/S's end).
    pub fn address(mut self, address: Ipv4Addr) -> Self {
        self.address = Some(address);
        self
    }

    /// Sets the peer IPv4 address of the interface (the stack's end).
    pub fn destination(mut self, destination: Ipv4Addr) -> Self {
        self.destination = Some(destination);
        self
    }

    /// Sets the local IPv6 address of the interface (the O/S's end).
    pub fn address6(mut self, address: Ipv6Addr) -> Self {
        self.address6 = Some(address);
        self
    }

    /// Sets the peer IPv6 address of the interface (the stack's end).
    pub fn destination6(mut self, destination: Ipv6Addr) -> Self {
        self.destination6 = Some(destination);
        self
    }

    /// Creates and configures the interface. macOS has no multi-queue TUN,
    /// so this always yields exactly one [`Tun`]; the `Vec` matches the
    /// shape `tokio-tun` returns on Linux.
    pub fn build(self) -> io::Result<Vec<Tun>> {
        let address = self
            .address
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing address"))?;
        let destination = self
            .destination
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing destination"))?;
        Ok(vec![Tun::new(
            &self.name,
            address,
            destination,
            self.address6,
            self.destination6,
        )?])
    }
}

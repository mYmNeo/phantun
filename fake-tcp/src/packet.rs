use bytes::{Bytes, BytesMut};
use pnet::packet::{ip, ipv4, ipv6, tcp};
use std::net::{IpAddr, SocketAddr};

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
pub const MAX_PACKET_LEN: usize = 1500;
const TCP_PROTOCOL: u8 = ip::IpNextHeaderProtocols::Tcp.0;

pub enum IPPacket<'p> {
    V4(ipv4::Ipv4Packet<'p>),
    V6(ipv6::Ipv6Packet<'p>),
}

impl IPPacket<'_> {
    pub fn get_source(&self) -> IpAddr {
        match self {
            IPPacket::V4(p) => IpAddr::V4(p.get_source()),
            IPPacket::V6(p) => IpAddr::V6(p.get_source()),
        }
    }

    pub fn get_destination(&self) -> IpAddr {
        match self {
            IPPacket::V4(p) => IpAddr::V4(p.get_destination()),
            IPPacket::V6(p) => IpAddr::V6(p.get_destination()),
        }
    }
}

pub fn build_tcp_packet(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: Option<&[u8]>,
) -> Bytes {
    let mut buf = BytesMut::new();
    build_tcp_packet_into(&mut buf, local_addr, remote_addr, seq, ack, flags, payload);
    buf.freeze()
}

/// Build a TCP/IP packet into the provided buffer.
///
/// The buffer is cleared and filled with exactly the packet bytes. If the
/// buffer's capacity is at least `MAX_PACKET_LEN` (which holds for the pooled
/// per-connection send buffer), this never reallocates. Headers are assembled
/// on the stack and appended together with the payload, so no byte of the
/// buffer is written more than once.
pub fn build_tcp_packet_into(
    buf: &mut BytesMut,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: Option<&[u8]>,
) {
    let payload = payload.unwrap_or(&[]);
    let wscale = (flags & tcp::TcpFlags::SYN) != 0;
    let tcp_header_len = TCP_HEADER_LEN + if wscale { 4 } else { 0 }; // nop + wscale
    let tcp_total_len = tcp_header_len + payload.len();

    // Header words are built as native-endian u64s in registers, summed with
    // `lanes` and then stored, so no header byte is read back from memory
    // (re-reading narrow stores with wide loads stalls store forwarding).
    // Max header: IPv6 (40) + TCP with options (24).
    let mut hdr = [0u8; IPV6_HEADER_LEN + TCP_HEADER_LEN + 4];
    let tl = (tcp_total_len as u16).to_be_bytes();
    // Pseudo-header tail as 16-bit words: (0, proto) + tcp length. IPv4 has
    // these two words; IPv6 has a 32-bit length (upper half zero since
    // tcp_total_len < 2^16) and 24 zero bits before the next-header byte.
    let mut sum = lanes(u64::from_ne_bytes([0, TCP_PROTOCOL, tl[0], tl[1], 0, 0, 0, 0]));

    let ip_header_len = match (local_addr, remote_addr) {
        (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
            let total = ((IPV4_HEADER_LEN + tcp_total_len) as u16).to_be_bytes();
            let [s0, s1, s2, s3] = local.ip().octets();
            let [d0, d1, d2, d3] = remote.ip().octets();
            // version/IHL, TOS, total length, id = 0, flags = DF, frag = 0
            let w0 = u64::from_ne_bytes([0x45, 0, total[0], total[1], 0, 0, 0x40, 0]);
            let ttl_proto = u16::from_ne_bytes([64, TCP_PROTOCOL]);
            let addrs = u64::from_ne_bytes([s0, s1, s2, s3, d0, d1, d2, d3]);
            // Both the IP header checksum and the TCP pseudo-header cover the
            // address pair; sum it once.
            let addr_sum = lanes(addrs);
            let ip_cksm = fold_checksum(lanes(w0) + ttl_proto as u64 + addr_sum);
            hdr[0..8].copy_from_slice(&w0.to_ne_bytes());
            hdr[8..10].copy_from_slice(&ttl_proto.to_ne_bytes());
            hdr[10..12].copy_from_slice(&ip_cksm);
            hdr[12..20].copy_from_slice(&addrs.to_ne_bytes());
            sum += addr_sum;
            IPV4_HEADER_LEN
        }
        (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
            let src = local.ip().octets();
            let dst = remote.ip().octets();
            // version/traffic class/flow label = 0, payload length, next
            // header, hop limit
            let w0 = u64::from_ne_bytes([0x60, 0, 0, 0, tl[0], tl[1], TCP_PROTOCOL, 64]);
            let a: [u64; 4] = [
                u64::from_ne_bytes(src[..8].try_into().unwrap()),
                u64::from_ne_bytes(src[8..].try_into().unwrap()),
                u64::from_ne_bytes(dst[..8].try_into().unwrap()),
                u64::from_ne_bytes(dst[8..].try_into().unwrap()),
            ];
            hdr[0..8].copy_from_slice(&w0.to_ne_bytes());
            hdr[8..24].copy_from_slice(&src);
            hdr[24..40].copy_from_slice(&dst);
            sum += lanes(a[0]) + lanes(a[1]) + lanes(a[2]) + lanes(a[3]);
            IPV6_HEADER_LEN
        }
        _ => unreachable!(),
    };

    let header_len = ip_header_len + tcp_header_len;
    let [p0, p1] = local_addr.port().to_be_bytes();
    let [q0, q1] = remote_addr.port().to_be_bytes();
    let [s0, s1, s2, s3] = seq.to_be_bytes();
    let [a0, a1, a2, a3] = ack.to_be_bytes();
    let off = ((tcp_header_len / 4) as u8) << 4; // data offset
    let t0 = u64::from_ne_bytes([p0, p1, q0, q1, s0, s1, s2, s3]);
    // ack, data offset, flags, window 0xffff
    let t1 = u64::from_ne_bytes([a0, a1, a2, a3, off, flags, 0xff, 0xff]);
    // NOP, then window scale (kind 3, len 3, shift 14).
    let opts = if wscale { [1u8, 3, 3, 14] } else { [0; 4] };
    sum += lanes(t0) + lanes(t1) + lanes(u32::from_ne_bytes(opts) as u64);
    // Header and pseudo-header are even-length, so the payload can be summed
    // separately without disturbing 16-bit word alignment.
    sum += ones_sum(payload);

    let tcp_hdr = &mut hdr[ip_header_len..header_len];
    tcp_hdr[0..8].copy_from_slice(&t0.to_ne_bytes());
    tcp_hdr[8..16].copy_from_slice(&t1.to_ne_bytes());
    tcp_hdr[16..18].copy_from_slice(&fold_checksum(sum));
    if wscale {
        tcp_hdr[20..24].copy_from_slice(&opts);
    }

    buf.clear();
    buf.reserve(header_len + payload.len());
    buf.extend_from_slice(&hdr[..header_len]);
    buf.extend_from_slice(payload);
}

/// Sum of the four native-endian 16-bit words packed in `w`, as an unfolded
/// one's-complement partial sum compatible with [`ones_sum`].
#[inline(always)]
fn lanes(w: u64) -> u64 {
    (w & 0xffff) + ((w >> 16) & 0xffff) + ((w >> 32) & 0xffff) + (w >> 48)
}

/// Unfolded one's-complement sum of `bytes` taken as native-endian 16-bit
/// words (RFC 1071 §2(B): the sum is byte-order independent, so the folded
/// result is stored back with `to_ne_bytes`). An odd trailing byte is padded
/// with zero. Each 8-byte word is split into two masked halves holding two
/// zero-extended 16-bit words each (SWAR), so a 32-bit lane can absorb 65536
/// words before overflowing; inputs here are bounded by `MAX_PACKET_LEN`.
#[inline(always)]
fn ones_sum(bytes: &[u8]) -> u64 {
    const MASK: u64 = 0x0000_ffff_0000_ffff;
    debug_assert!(bytes.len() <= 0xffff);
    let (chunks, rem) = bytes.as_chunks::<8>();
    let (mut lo, mut hi) = (0u64, 0u64);
    for c in chunks {
        let w = u64::from_ne_bytes(*c);
        lo += w & MASK;
        hi += (w >> 16) & MASK;
    }
    let s = lo + hi;
    let mut acc = (s & 0xffff_ffff) + (s >> 32);
    let (words, odd) = rem.as_chunks::<2>();
    for w in words {
        acc += u16::from_ne_bytes(*w) as u64;
    }
    if let [b] = odd {
        acc += u16::from_ne_bytes([*b, 0]) as u64;
    }
    acc
}

/// Folds an unfolded sum from [`ones_sum`] into the final 16-bit checksum.
#[inline(always)]
fn fold_checksum(sum: u64) -> [u8; 2] {
    let mut s = (sum & 0xffff_ffff) + (sum >> 32);
    s = (s & 0xffff_ffff) + (s >> 32);
    let mut s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    (!(s as u16)).to_ne_bytes()
}

pub fn parse_ip_packet(buf: &Bytes) -> Option<(IPPacket<'_>, tcp::TcpPacket<'_>)> {
    if buf[0] >> 4 == 4 {
        let v4 = ipv4::Ipv4Packet::new(buf).unwrap();
        if v4.get_next_level_protocol() != ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        let tcp = tcp::TcpPacket::new(&buf[IPV4_HEADER_LEN..]).unwrap();
        Some((IPPacket::V4(v4), tcp))
    } else if buf[0] >> 4 == 6 {
        let v6 = ipv6::Ipv6Packet::new(buf).unwrap();
        if v6.get_next_header() != ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        let tcp = tcp::TcpPacket::new(&buf[IPV6_HEADER_LEN..]).unwrap();
        Some((IPPacket::V6(v6), tcp))
    } else {
        None
    }
}

#[cfg(all(test, feature = "benchmark"))]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::{black_box, Bencher};

    #[bench]
    fn bench_build_tcp_packet_1460(b: &mut Bencher) {
        let local_addr = "127.0.0.1:1234".parse().unwrap();
        let remote_addr = "127.0.0.2:1234".parse().unwrap();
        let payload = black_box([123u8; 1460]);
        b.iter(|| {
            build_tcp_packet(
                local_addr,
                remote_addr,
                123,
                456,
                tcp::TcpFlags::ACK,
                Some(&payload),
            )
        });
    }

    #[bench]
    fn bench_build_tcp_packet_512(b: &mut Bencher) {
        let local_addr = "127.0.0.1:1234".parse().unwrap();
        let remote_addr = "127.0.0.2:1234".parse().unwrap();
        let payload = black_box([123u8; 512]);
        b.iter(|| {
            build_tcp_packet(
                local_addr,
                remote_addr,
                123,
                456,
                tcp::TcpFlags::ACK,
                Some(&payload),
            )
        });
    }

    #[bench]
    fn bench_build_tcp_packet_128(b: &mut Bencher) {
        let local_addr = "127.0.0.1:1234".parse().unwrap();
        let remote_addr = "127.0.0.2:1234".parse().unwrap();
        let payload = black_box([123u8; 128]);
        b.iter(|| {
            build_tcp_packet(
                local_addr,
                remote_addr,
                123,
                456,
                tcp::TcpFlags::ACK,
                Some(&payload),
            )
        });
    }
}

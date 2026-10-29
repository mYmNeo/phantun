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

    // Max header: IPv6 (40) + TCP with options (24).
    let mut hdr = [0u8; IPV6_HEADER_LEN + TCP_HEADER_LEN + 4];
    let mut sum: u64;

    let ip_header_len = match (local_addr, remote_addr) {
        (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
            let total_len = (IPV4_HEADER_LEN + tcp_total_len) as u16;
            let ip = &mut hdr[..IPV4_HEADER_LEN];
            ip[0] = 0x45; // version 4, IHL 5
            ip[2..4].copy_from_slice(&total_len.to_be_bytes());
            ip[6] = 0x40; // DF
            ip[8] = 64; // TTL
            ip[9] = TCP_PROTOCOL;
            ip[12..16].copy_from_slice(&local.ip().octets());
            ip[16..20].copy_from_slice(&remote.ip().octets());
            // Both the IP header checksum and the TCP pseudo-header cover the
            // address pair; sum it once. The remaining non-zero IP header words
            // are 0x4500, total_len, 0x4000 (DF) and TTL/proto.
            let addr_sum = ones_sum(&ip[12..20]);
            let proto_word = u16::from_ne_bytes([0, TCP_PROTOCOL]) as u64;
            let ip_sum = addr_sum
                + u16::from_ne_bytes([0x45, 0]) as u64
                + u16::from_ne_bytes(total_len.to_be_bytes()) as u64
                + u16::from_ne_bytes([0x40, 0]) as u64
                + u16::from_ne_bytes([64, TCP_PROTOCOL]) as u64;
            ip[10..12].copy_from_slice(&fold_checksum(ip_sum));

            // TCP pseudo-header: src, dst, zero, proto, tcp length.
            sum = addr_sum
                + proto_word
                + u16::from_ne_bytes((tcp_total_len as u16).to_be_bytes()) as u64;
            IPV4_HEADER_LEN
        }
        (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
            let ip = &mut hdr[..IPV6_HEADER_LEN];
            ip[0] = 0x60; // version 6
            ip[4..6].copy_from_slice(&(tcp_total_len as u16).to_be_bytes());
            ip[6] = TCP_PROTOCOL;
            ip[7] = 64; // hop limit
            ip[8..24].copy_from_slice(&local.ip().octets());
            ip[24..40].copy_from_slice(&remote.ip().octets());

            // TCP pseudo-header: src, dst, tcp length (u32), zero, next header.
            let mut pseudo = [0u8; 40];
            pseudo[..32].copy_from_slice(&ip[8..40]);
            pseudo[32..36].copy_from_slice(&(tcp_total_len as u32).to_be_bytes());
            pseudo[39] = TCP_PROTOCOL;
            sum = ones_sum(&pseudo);
            IPV6_HEADER_LEN
        }
        _ => unreachable!(),
    };

    let header_len = ip_header_len + tcp_header_len;
    let tcp_hdr = &mut hdr[ip_header_len..header_len];
    tcp_hdr[0..2].copy_from_slice(&local_addr.port().to_be_bytes());
    tcp_hdr[2..4].copy_from_slice(&remote_addr.port().to_be_bytes());
    tcp_hdr[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp_hdr[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp_hdr[12] = ((tcp_header_len / 4) as u8) << 4; // data offset
    tcp_hdr[13] = flags;
    tcp_hdr[14..16].copy_from_slice(&0xffffu16.to_be_bytes()); // window
    if wscale {
        // NOP, then window scale (kind 3, len 3, shift 14).
        tcp_hdr[20..24].copy_from_slice(&[1, 3, 3, 14]);
    }
    // Header and pseudo-header are even-length, so the payload can be summed
    // separately without disturbing 16-bit word alignment.
    sum += ones_sum(tcp_hdr);
    sum += ones_sum(payload);
    tcp_hdr[16..18].copy_from_slice(&fold_checksum(sum));

    buf.clear();
    buf.reserve(header_len + payload.len());
    buf.extend_from_slice(&hdr[..header_len]);
    buf.extend_from_slice(payload);
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
    let mut chunks = bytes.chunks_exact(8);
    let (mut lo, mut hi) = (0u64, 0u64);
    for c in &mut chunks {
        let w = u64::from_ne_bytes(c.try_into().unwrap());
        lo += w & MASK;
        hi += (w >> 16) & MASK;
    }
    let s = lo + hi;
    let mut acc = (s & 0xffff_ffff) + (s >> 32);
    let mut words = chunks.remainder().chunks_exact(2);
    for w in &mut words {
        acc += u16::from_ne_bytes([w[0], w[1]]) as u64;
    }
    if let [b] = words.remainder() {
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

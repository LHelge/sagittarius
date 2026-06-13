//! EDNS/OPT-aware DNS response synthesis.
//!
//! Builds block, local-record, and minimal error responses directly into an
//! output buffer (no intermediate message model — SPEC §2.1).  All synthesis
//! paths return [`bytes::Bytes`]; they are infallible for the trusted-input
//! paths (parsed query + config) and non-panicking for the hostile-input path
//! ([`EdnsInfo::scan`]).
//!
//! # Design highlights
//!
//! - **Question raw-copy**: the question section is copied verbatim from
//!   `query.question_wire()` (`raw[12..question_end]`), preserving DNS 0x20
//!   mixed-case without re-encoding the normalized [`Name`].
//! - **Answer owner compression pointer**: answer RR owner names use the
//!   2-byte pointer `0xC0 0x0C` (points to offset 12, where the QNAME always
//!   starts), keeping responses compact.
//! - **EDNS echo**: when the query carried an OPT pseudo-RR
//!   ([`EdnsInfo::scan`] returns `Some`), a matching OPT is appended to the
//!   additional section.  A well-formed client COOKIE option (option-code 10,
//!   RFC 7873) is reflected as a v0.1 simplification; full server-cookie
//!   generation per RFC 7873 is future scope.
//!
//! # Entry point
//!
//! ```rust
//! use std::net::{Ipv4Addr, Ipv6Addr};
//! use bytes::Bytes;
//! use sagittarius::codec::message::Query;
//! use sagittarius::codec::synth::{BlockMode, Response};
//!
//! # fn build_query() -> Bytes {
//! #     use sagittarius::codec::{header::Header, name::Name, writer::Writer};
//! #     let mut w = Writer::with_capacity(64);
//! #     Header::new(0x1234).with_rd(true).with_qdcount(1).write(&mut w);
//! #     let name: Name = "ads.example.com".parse().unwrap();
//! #     name.write(&mut w);
//! #     w.write_u16(1u16);  // QTYPE A
//! #     w.write_u16(1u16);  // QCLASS IN
//! #     w.finish()
//! # }
//! let raw: Bytes = build_query();
//! let query = Query::try_from(raw).expect("valid query");
//! let mode = BlockMode::null_ip();
//! let response = Response::block(&query, &mode, 60, None);
//! // response is a Bytes ready to send back to the client
//! let _ = response;
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use crate::codec::{
    header::{Header, Rcode},
    message::{Qtype, Query},
    name::Name,
    reader::Reader,
    ttl::OPT_TYPE,
    writer::Writer,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Server advertised UDP payload size in synthesized OPT responses.
///
/// 1232 bytes is the recommended value per the 2020 DNS Flag Day guidance
/// (also the default for most modern resolvers). It is safe with IPv6 and
/// avoids fragmentation on most network paths.
pub const SERVER_UDP_PAYLOAD_SIZE: u16 = 1232;

/// EDNS COOKIE option code (RFC 7873 §4).
const EDNS_OPTION_COOKIE: u16 = 10;

/// RFC 7873 client-cookie length.
const EDNS_CLIENT_COOKIE_LEN: usize = 8;

/// RFC 7873 permits server cookies from 8 to 32 bytes, appended after the
/// 8-byte client cookie.  Queries may carry just the client cookie, or both.
const EDNS_COOKIE_MAX_LEN: usize = 40;

/// Answer RR owner — compression pointer to offset 12 (the QNAME).
///
/// Two bytes `[0xC0, 0x0C]`: top two bits of 0xC0 signal a compression
/// pointer; `0x0C` = 12, which is the byte immediately after the DNS header
/// and therefore always the start of the QNAME.
const OWNER_PTR: [u8; 2] = [0xC0, 0x0C];

/// CLASS IN (Internet) — used in synthesized answer RRs.
const CLASS_IN: u16 = 1;

// ── EdnsInfo ─────────────────────────────────────────────────────────────────

/// EDNS information extracted from the OPT pseudo-RR in a query's additional
/// section.
///
/// Produced by [`EdnsInfo::scan`].  When `None` is returned, the query did
/// not carry EDNS and no OPT should be appended to the response.
///
/// # Usage
///
/// Pass the `Option<EdnsInfo>` returned by [`EdnsInfo::scan`] to the
/// synthesis functions (`Response::block`, `Response::local`, etc.).  They
/// use it to conditionally append an OPT record and to advertise the correct
/// server UDP payload size.
#[derive(Debug, Clone)]
pub struct EdnsInfo {
    /// Client's advertised UDP payload size (the OPT CLASS field, RFC 6891
    /// §6.2.3).
    pub udp_payload_size: u16,
    /// The EDNS COOKIE option data (RFC 7873) if present.
    ///
    /// Contains validated raw option-data bytes (client cookie, and optionally
    /// a server cookie).  In v0.1, the response synthesis reflects these bytes;
    /// full server-cookie generation per RFC 7873 is future scope.
    pub cookie: Option<Bytes>,
}

impl EdnsInfo {
    /// Scan the query's additional section for an OPT pseudo-RR and extract
    /// EDNS information.
    ///
    /// Walks the answer, authority, and additional sections by header counts,
    /// skipping RR owner names with [`Name::skip_rr`] and bounds-checking all
    /// field reads.  Returns `None` if:
    /// - The query has no ARCOUNT / no additional records.
    /// - No OPT record (TYPE 41) is found.
    /// - Any parse error occurs while walking to or through the OPT.
    ///
    /// **Never panics on untrusted input.**
    #[must_use]
    pub fn scan(query: &Query) -> Option<Self> {
        Self::scan_inner(query)
    }

    /// Inner implementation — returns `Option` so `?` can be used throughout.
    fn scan_inner(query: &Query) -> Option<Self> {
        let raw = query.raw();
        let mut reader = Reader::new(raw.clone());

        // Re-read the header from the raw bytes so we have all the section counts.
        let header = Header::read(&mut reader).ok()?;

        // Skip question section (QDCOUNT entries: name + QTYPE + QCLASS).
        for _ in 0..header.qdcount {
            Name::skip_rr(&mut reader).ok()?;
            reader.read_u16().ok()?; // QTYPE
            reader.read_u16().ok()?; // QCLASS
        }

        // Walk answer + authority sections, skipping each RR.
        let an_ns_count = (header.ancount as usize).saturating_add(header.nscount as usize);
        for _ in 0..an_ns_count {
            Name::skip_rr(&mut reader).ok()?;
            reader.read_u16().ok()?; // TYPE
            reader.read_u16().ok()?; // CLASS
            reader.read_u32().ok()?; // TTL
            let rdlength = reader.read_u16().ok()? as usize;
            reader.read_slice(rdlength).ok()?;
        }

        // Walk additional section, looking for OPT (TYPE 41).
        for _ in 0..header.arcount {
            Name::skip_rr(&mut reader).ok()?;
            let rr_type = reader.read_u16().ok()?;
            let rr_class = reader.read_u16().ok()?; // CLASS = UDP payload size for OPT
            reader.read_u32().ok()?; // TTL (extended RCODE/version/flags for OPT)
            let rdlength = reader.read_u16().ok()? as usize;
            let rdata = reader.read_slice(rdlength).ok()?;

            if rr_type == OPT_TYPE {
                // Found an OPT RR.
                let udp_payload_size = rr_class;
                let cookie = Self::extract_cookie(&rdata);
                return Some(Self {
                    udp_payload_size,
                    cookie,
                });
            }
        }

        // No OPT found.
        None
    }

    /// Extract the EDNS COOKIE option data (option-code 10) from OPT RDATA.
    ///
    /// OPT RDATA is a sequence of `{option-code u16, option-length u16, data…}`
    /// tuples.  Returns the data bytes of the first well-formed COOKIE option
    /// found, or `None` if no COOKIE option is present, the RDATA is malformed,
    /// or the COOKIE length is invalid per RFC 7873.
    fn extract_cookie(rdata: &Bytes) -> Option<Bytes> {
        let mut pos = 0usize;
        let data = rdata;

        while pos + 4 <= data.len() {
            let code = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let length = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            let end = pos.checked_add(length)?;
            if end > data.len() {
                return None; // truncated option data
            }

            if code == EDNS_OPTION_COOKIE {
                return Self::valid_cookie_len(length).then(|| data.slice(pos..end));
            }

            pos = end;
        }

        None
    }

    fn valid_cookie_len(length: usize) -> bool {
        length == EDNS_CLIENT_COOKIE_LEN
            || (EDNS_CLIENT_COOKIE_LEN * 2..=EDNS_COOKIE_MAX_LEN).contains(&length)
    }
}

// ── BlockMode ─────────────────────────────────────────────────────────────────

/// How a blocked query should be answered.
///
/// - [`BlockMode::NxDomain`] — return RCODE=NXDOMAIN for every qtype.
/// - [`BlockMode::Address`] — return a sinkhole address for A/AAAA queries;
///   NODATA (NOERROR, ANCOUNT=0) for all other qtypes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockMode {
    /// Respond with NXDOMAIN for any qtype (the name does not exist).
    NxDomain,
    /// Respond with a sinkhole IP address for A and AAAA queries.
    Address {
        /// IPv4 sinkhole address returned for A queries.
        v4: Ipv4Addr,
        /// IPv6 sinkhole address returned for AAAA queries.
        v6: Ipv6Addr,
    },
}

impl BlockMode {
    /// The canonical null-IP sinkhole: `0.0.0.0` for A, `::` for AAAA.
    ///
    /// This is the seeded default for new installations.
    #[must_use]
    pub fn null_ip() -> Self {
        Self::Address {
            v4: Ipv4Addr::UNSPECIFIED,
            v6: Ipv6Addr::UNSPECIFIED,
        }
    }
}

// ── Response ──────────────────────────────────────────────────────────────────

/// DNS response synthesis.
///
/// All methods build a response directly into a [`Writer`] and return the
/// finished [`Bytes`] — no intermediate DNS message model.
///
/// # Response layout
///
/// Every synthesized response follows this layout:
///
/// ```text
/// [12-byte header] [raw question bytes] [answer RRs] [optional OPT]
/// ```
///
/// - **Header**: fresh, with correct flags/counts.
/// - **Question**: raw-copied from `query.question_wire()` (bytes 12 to
///   `question_end` of the original query datagram), preserving DNS 0x20
///   case exactly.
/// - **Answer RRs**: owner = `0xC0 0x0C` (compression pointer to offset 12).
/// - **OPT**: present iff the query carried EDNS (`edns.is_some()`).
pub struct Response;

impl Response {
    // ── Block responses ───────────────────────────────────────────────────────

    /// Synthesize a block response for `query` according to `mode`.
    ///
    /// | mode | qtype | result |
    /// |---|---|---|
    /// | NxDomain | any | NXDOMAIN, 0 answers |
    /// | Address | A | NOERROR, 1 A answer |
    /// | Address | AAAA | NOERROR, 1 AAAA answer |
    /// | Address | other | NODATA (NOERROR, 0 answers) |
    ///
    /// `ttl` is the TTL placed on synthesized answer records (seconds).
    /// `edns` is the EDNS info from [`EdnsInfo::scan`]; when `Some`, an OPT
    /// record is appended and ARCOUNT is set to 1.
    #[must_use]
    pub fn block(query: &Query, mode: &BlockMode, ttl: u32, edns: Option<&EdnsInfo>) -> Bytes {
        match mode {
            BlockMode::NxDomain => Self::build(query, Rcode::NxDomain, false, &[], edns),
            BlockMode::Address { v4, v6 } => match query.question().qtype {
                Qtype::A => {
                    let rdata = v4.octets();
                    Self::build(
                        query,
                        Rcode::NoError,
                        false,
                        &[AnswerRr {
                            rtype: 1,
                            ttl,
                            rdata: &rdata,
                        }],
                        edns,
                    )
                }
                Qtype::Aaaa => {
                    let rdata = v6.octets();
                    Self::build(
                        query,
                        Rcode::NoError,
                        false,
                        &[AnswerRr {
                            rtype: 28,
                            ttl,
                            rdata: &rdata,
                        }],
                        edns,
                    )
                }
                Qtype::Ptr | Qtype::Other(_) => {
                    // NODATA — NOERROR with zero answers.
                    Self::build(query, Rcode::NoError, false, &[], edns)
                }
            },
        }
    }

    // ── Local-record responses ────────────────────────────────────────────────

    /// Synthesize an authoritative answer for a local A or AAAA record.
    ///
    /// `records` holds the answer RRs relevant to the requested qtype (the
    /// caller is responsible for filtering to the right type).  `ttl` is the
    /// record TTL.  The response has AA=1, RCODE=NOERROR.
    ///
    /// `edns` is the EDNS info from [`EdnsInfo::scan`].
    #[must_use]
    pub fn local(
        query: &Query,
        records: &[LocalRecord<'_>],
        ttl: u32,
        edns: Option<&EdnsInfo>,
    ) -> Bytes {
        let answers: Vec<AnswerRr<'_>> = records
            .iter()
            .map(|r| AnswerRr {
                rtype: r.rtype,
                ttl,
                rdata: r.rdata,
            })
            .collect();
        Self::build_authoritative(query, Rcode::NoError, &answers, edns)
    }

    /// Synthesize an authoritative NODATA response.
    ///
    /// Used when the qname is local but has no record for the requested qtype.
    /// AA=1, RCODE=NOERROR, ANCOUNT=0.
    ///
    /// `edns` is the EDNS info from [`EdnsInfo::scan`].
    #[must_use]
    pub fn local_nodata(query: &Query, edns: Option<&EdnsInfo>) -> Bytes {
        Self::build_authoritative(query, Rcode::NoError, &[], edns)
    }

    /// Synthesize an authoritative PTR answer for a reverse query whose address
    /// we own locally (E13.2).
    ///
    /// The single answer RR has TYPE=PTR (12) and RDATA equal to `target`
    /// encoded as an **uncompressed** DNS name.  The owner is the usual
    /// `0xC0 0x0C` pointer to the question (the in-addr.arpa / ip6.arpa name).
    /// AA=1, RCODE=NOERROR.
    ///
    /// `edns` is the EDNS info from [`EdnsInfo::scan`].
    #[must_use]
    pub fn local_ptr(query: &Query, target: &Name, ttl: u32, edns: Option<&EdnsInfo>) -> Bytes {
        // PTR RDATA is a domain name.  Encode it (uncompressed) into a scratch
        // buffer first so its byte length can be written as RDLENGTH.
        let mut name_buf = Writer::with_capacity(target.as_str().len() + 1);
        target.write(&mut name_buf);
        let rdata = name_buf.finish();

        let answers = [AnswerRr {
            rtype: 12, // PTR
            ttl,
            rdata: &rdata,
        }];
        Self::build_authoritative(query, Rcode::NoError, &answers, edns)
    }

    // ── Error responses ───────────────────────────────────────────────────────

    /// Synthesize a minimal error response for a successfully parsed query.
    ///
    /// Echoes the question section and copies RD from the query.  Sets RA=1
    /// (this server offers recursion).  Suitable for SERVFAIL, REFUSED, and
    /// other rcodes produced after the query was parsed.
    ///
    /// `edns` is the EDNS info from [`EdnsInfo::scan`].
    #[must_use]
    pub fn error_response(query: &Query, rcode: Rcode, edns: Option<&EdnsInfo>) -> Bytes {
        Self::build(query, rcode, false, &[], edns)
    }

    /// Synthesize a minimal FORMERR response from only a transaction ID.
    ///
    /// Used when the query was so malformed that parsing failed before the
    /// question could be read.  No question section is echoed (QDCOUNT=0).
    /// RD and RA are both 0 (no query flags to copy).
    #[must_use]
    pub fn formerr(id: u16) -> Bytes {
        let mut w = Writer::with_capacity(12);
        Header::new(id)
            .with_qr(true)
            .with_rcode(Rcode::FormErr)
            .write(&mut w);
        w.finish()
    }

    /// Synthesize a minimal NOTIMP response from only a transaction ID.
    ///
    /// Sent when the query uses an opcode this resolver does not implement
    /// (anything other than standard QUERY). No question section is echoed
    /// (QDCOUNT=0); the opcode is left as QUERY in the reply, which clients
    /// still read as "not implemented" from the RCODE.
    #[must_use]
    pub fn notimp(id: u16) -> Bytes {
        let mut w = Writer::with_capacity(12);
        Header::new(id)
            .with_qr(true)
            .with_rcode(Rcode::NotImpl)
            .write(&mut w);
        w.finish()
    }

    /// Synthesize a minimal truncated (TC=1) response.
    ///
    /// Echoes the question, sets QR=1, TC=1, RA=1, RCODE=NOERROR, zero RRs.
    /// Signals the client to retry the query over TCP.
    ///
    /// `edns` is the EDNS info from [`EdnsInfo::scan`]; when `Some`, an OPT
    /// record is appended and ARCOUNT is set to 1.
    #[must_use]
    pub fn truncated(query: &Query, edns: Option<&EdnsInfo>) -> Bytes {
        Self::build_tc(query, edns)
    }

    // ── Internal builders ─────────────────────────────────────────────────────

    /// Build a truncated (TC=1) response with no answer RRs.
    ///
    /// Sets QR=1, TC=1, RA=1, RCODE=NOERROR, QDCOUNT=1, ANCOUNT=0.
    /// Echoes the question section verbatim and optionally appends an OPT.
    fn build_tc(query: &Query, edns: Option<&EdnsInfo>) -> Bytes {
        let arcount = if edns.is_some() { 1u16 } else { 0u16 };

        let mut w = Writer::with_capacity(512);

        // Header: QR=1, TC=1, RD copied, RA=1, RCODE=NOERROR
        Header::new(query.header().id)
            .with_qr(true)
            .with_tc(true)
            .with_rd(query.header().rd())
            .with_ra(true)
            .with_rcode(Rcode::NoError)
            .with_qdcount(1)
            .with_arcount(arcount)
            .write(&mut w);

        // Question section — raw-copied from the original query bytes.
        w.write_slice(&query.question_wire());

        // OPT record (if the query carried EDNS).
        if let Some(edns) = edns {
            Self::write_opt(&mut w, edns);
        }

        w.finish()
    }

    /// Build a response with optional answer RRs.
    ///
    /// `aa` sets the AA (Authoritative Answer) flag.
    fn build(
        query: &Query,
        rcode: Rcode,
        aa: bool,
        answers: &[AnswerRr<'_>],
        edns: Option<&EdnsInfo>,
    ) -> Bytes {
        let ancount = answers.len() as u16;
        let arcount = if edns.is_some() { 1u16 } else { 0u16 };

        let mut w = Writer::with_capacity(512);

        // Header
        let mut hdr = Header::new(query.header().id)
            .with_qr(true)
            .with_rd(query.header().rd())
            .with_ra(true)
            .with_rcode(rcode)
            .with_qdcount(1)
            .with_ancount(ancount)
            .with_arcount(arcount);
        if aa {
            hdr.set_aa(true);
        }
        hdr.write(&mut w);

        // Question section — raw-copied from the original query bytes.
        // This preserves DNS 0x20 label-case exactly as sent by the client.
        w.write_slice(&query.question_wire());

        // Answer RRs (if any).
        for rr in answers {
            Self::write_answer_rr(&mut w, rr);
        }

        // OPT record (if the query carried EDNS).
        if let Some(edns) = edns {
            Self::write_opt(&mut w, edns);
        }

        w.finish()
    }

    /// Build an authoritative (AA=1) response.
    fn build_authoritative(
        query: &Query,
        rcode: Rcode,
        answers: &[AnswerRr<'_>],
        edns: Option<&EdnsInfo>,
    ) -> Bytes {
        Self::build(query, rcode, true, answers, edns)
    }

    /// Write a single answer RR to `w`.
    ///
    /// Owner = compression pointer `0xC0 0x0C` (pointing to the QNAME at
    /// offset 12 in the response).
    fn write_answer_rr(w: &mut Writer, rr: &AnswerRr<'_>) {
        // Owner: compression pointer → offset 12 (start of QNAME).
        w.write_slice(&OWNER_PTR);
        // TYPE
        w.write_u16(rr.rtype);
        // CLASS IN
        w.write_u16(CLASS_IN);
        // TTL
        w.write_u32(rr.ttl);
        // RDLENGTH + RDATA
        w.write_u16(rr.rdata.len() as u16);
        w.write_slice(rr.rdata);
    }

    /// Write the OPT pseudo-RR echo into `w`.
    ///
    /// Layout (RFC 6891 §6.1.1):
    /// - Owner name: `0x00` (root).
    /// - TYPE: 41.
    /// - CLASS: [`SERVER_UDP_PAYLOAD_SIZE`].
    /// - TTL: 0 (extended RCODE=0, version=0, flags=0).
    /// - RDATA: COOKIE option (`{0x00 0x0A, length, data}`) if the query had a
    ///   valid one; otherwise zero bytes (RDLENGTH=0).
    ///
    /// # Cookie reflection (v0.1 simplification)
    ///
    /// Valid cookie option data is reflected.  Full server-cookie generation per
    /// RFC 7873 §5 (HMAC-SHA-256 keyed with a server secret) is future scope.
    fn write_opt(w: &mut Writer, edns: &EdnsInfo) {
        // Root owner name.
        w.write_u8(0x00);
        // TYPE OPT = 41.
        w.write_u16(OPT_TYPE);
        // CLASS = server UDP payload size.
        w.write_u16(SERVER_UDP_PAYLOAD_SIZE);
        // TTL = 0 (extended RCODE=0, EDNS version=0, flags=0).
        w.write_u32(0);

        // RDATA: reflect the COOKIE option if present.
        if let Some(cookie) = &edns.cookie {
            // OPTION-CODE(2) + OPTION-LENGTH(2) + cookie data.
            let opt_len =
                u16::try_from(4 + cookie.len()).expect("validated EDNS COOKIE must fit in u16");
            let cookie_len =
                u16::try_from(cookie.len()).expect("validated EDNS COOKIE must fit in u16");
            w.write_u16(opt_len); // RDLENGTH
            w.write_u16(EDNS_OPTION_COOKIE); // OPTION-CODE = 10
            w.write_u16(cookie_len); // OPTION-LENGTH
            w.write_slice(cookie); // option data
        } else {
            w.write_u16(0); // RDLENGTH = 0
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// A synthesized answer RR — owner is always the `0xC0 0x0C` compression
/// pointer, CLASS is always IN.
struct AnswerRr<'a> {
    /// Wire TYPE value (e.g. 1 for A, 28 for AAAA).
    rtype: u16,
    /// Time-to-live in seconds.
    ttl: u32,
    /// Raw RDATA bytes (4 for A, 16 for AAAA).
    rdata: &'a [u8],
}

/// A local record to include in a response.
///
/// The caller filters by qtype and passes the matching records here.
pub struct LocalRecord<'a> {
    /// Wire TYPE value (1 for A, 28 for AAAA).
    pub rtype: u16,
    /// Raw RDATA bytes.
    pub rdata: &'a [u8],
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{
        header::Header, message::Query, name::Name, reader::Reader, writer::Writer,
    };
    use bytes::Bytes;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── Test helpers ──────────────────────────────────────────────────────────

    /// Build a minimal DNS query datagram.
    fn build_query(id: u16, rd: bool, name: &str, qtype: u16) -> Bytes {
        build_query_raw(id, rd, name, qtype, &[])
    }

    /// Build a DNS query with optional trailing bytes (e.g. an OPT record).
    fn build_query_raw(id: u16, rd: bool, name: &str, qtype: u16, extra: &[u8]) -> Bytes {
        let mut w = Writer::with_capacity(128);
        Header::new(id).with_rd(rd).with_qdcount(1).write(&mut w);
        let n: Name = name.parse().expect("valid name in test helper");
        n.write(&mut w);
        w.write_u16(qtype);
        w.write_u16(1u16); // QCLASS IN
        w.write_slice(extra);
        w.finish()
    }

    /// Build a query that carries an OPT record in the additional section.
    ///
    /// `udp_payload_size` is placed in the OPT CLASS field.
    /// `cookie` is optional COOKIE option data (option-code 10, RFC 7873).
    fn build_query_with_opt(
        id: u16,
        rd: bool,
        name: &str,
        qtype: u16,
        udp_payload_size: u16,
        cookie: Option<&[u8]>,
    ) -> Bytes {
        let mut opt_bytes = Vec::new();
        // OPT RR: root owner (0x00), TYPE 41, CLASS udp_payload_size,
        //         TTL (extended RCODE etc.) = 0, RDATA.
        opt_bytes.push(0x00); // root owner
        opt_bytes.extend_from_slice(&41u16.to_be_bytes()); // TYPE OPT
        opt_bytes.extend_from_slice(&udp_payload_size.to_be_bytes()); // CLASS
        opt_bytes.extend_from_slice(&0u32.to_be_bytes()); // TTL

        if let Some(c) = cookie {
            // RDLENGTH = 4 (option header) + cookie length
            let rdlength: u16 = 4 + c.len() as u16;
            opt_bytes.extend_from_slice(&rdlength.to_be_bytes());
            opt_bytes.extend_from_slice(&EDNS_OPTION_COOKIE.to_be_bytes());
            opt_bytes.extend_from_slice(&(c.len() as u16).to_be_bytes());
            opt_bytes.extend_from_slice(c);
        } else {
            opt_bytes.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0
        }

        // Build full query with ARCOUNT=1 for the OPT.
        let mut w = Writer::with_capacity(128);
        Header::new(id)
            .with_rd(rd)
            .with_qdcount(1)
            .with_arcount(1)
            .write(&mut w);
        let n: Name = name.parse().expect("valid name in test helper");
        n.write(&mut w);
        w.write_u16(qtype);
        w.write_u16(1u16); // QCLASS IN
        w.write_slice(&opt_bytes);
        w.finish()
    }

    /// Parse the DNS header from a response buffer.
    fn parse_response_header(resp: &Bytes) -> Header {
        let mut r = Reader::new(resp.clone());
        Header::read(&mut r).expect("valid response header")
    }

    /// Read the first answer RR from a response, returning (type, class, ttl, rdata).
    ///
    /// Assumes QDCOUNT=1 and skips the question section before parsing.
    fn read_first_answer(resp: &Bytes) -> (u16, u16, u32, Bytes) {
        let mut r = Reader::new(resp.clone());
        // Skip header (12 bytes).
        r.read_slice(12).unwrap();
        // Skip question: name + qtype + qclass.
        Name::skip_rr(&mut r).unwrap();
        r.read_u16().unwrap(); // QTYPE
        r.read_u16().unwrap(); // QCLASS
        // Read answer RR owner (compression pointer 2 bytes).
        let _ptr = r.read_u16().unwrap();
        let rtype = r.read_u16().unwrap();
        let class = r.read_u16().unwrap();
        let ttl = r.read_u32().unwrap();
        let rdlength = r.read_u16().unwrap() as usize;
        let rdata = r.read_slice(rdlength).unwrap();
        (rtype, class, ttl, rdata)
    }

    /// Read the OPT RR from the additional section of a response.
    ///
    /// Assumes QDCOUNT=1, scans past question + answer RRs.
    fn read_opt_rr(resp: &Bytes) -> Option<(u16, u16, u32, Bytes)> {
        let hdr = parse_response_header(resp);
        let mut r = Reader::new(resp.clone());
        r.read_slice(12).unwrap(); // skip header
        // Skip question.
        Name::skip_rr(&mut r).unwrap();
        r.read_u16().unwrap();
        r.read_u16().unwrap();
        // Skip answer RRs.
        for _ in 0..hdr.ancount {
            Name::skip_rr(&mut r).unwrap();
            r.read_u16().unwrap(); // TYPE
            r.read_u16().unwrap(); // CLASS
            r.read_u32().unwrap(); // TTL
            let rdlen = r.read_u16().unwrap() as usize;
            r.read_slice(rdlen).unwrap();
        }
        // Read additional records, find OPT.
        for _ in 0..hdr.arcount {
            Name::skip_rr(&mut r).unwrap();
            let rtype = r.read_u16().unwrap();
            let class = r.read_u16().unwrap();
            let ttl = r.read_u32().unwrap();
            let rdlen = r.read_u16().unwrap() as usize;
            let rdata = r.read_slice(rdlen).unwrap();
            if rtype == OPT_TYPE {
                return Some((rtype, class, ttl, rdata));
            }
        }
        None
    }

    // ── EdnsInfo::scan ────────────────────────────────────────────────────────

    #[test]
    fn edns_scan_no_opt_returns_none() {
        let raw = build_query(0x1234, true, "example.com", 1);
        let query = Query::try_from(raw).unwrap();
        assert!(EdnsInfo::scan(&query).is_none());
    }

    #[test]
    fn edns_scan_opt_without_cookie() {
        let raw = build_query_with_opt(0x1234, true, "example.com", 1, 4096, None);
        let query = Query::try_from(raw).unwrap();
        let info = EdnsInfo::scan(&query).expect("should find OPT");
        assert_eq!(info.udp_payload_size, 4096);
        assert!(info.cookie.is_none());
    }

    #[test]
    fn edns_scan_opt_with_cookie() {
        let cookie_bytes: &[u8] = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let raw =
            build_query_with_opt(0x5678, true, "ads.example.com", 1, 1232, Some(cookie_bytes));
        let query = Query::try_from(raw).unwrap();
        let info = EdnsInfo::scan(&query).expect("should find OPT with cookie");
        assert_eq!(info.udp_payload_size, 1232);
        let got_cookie = info.cookie.expect("cookie must be present");
        assert_eq!(&got_cookie[..], cookie_bytes);
    }

    #[test]
    fn edns_scan_ignores_cookie_with_invalid_length() {
        let invalid_cookie = [0xAA; 9];
        let raw = build_query_with_opt(
            0x5678,
            true,
            "ads.example.com",
            1,
            1232,
            Some(&invalid_cookie),
        );
        let query = Query::try_from(raw).unwrap();
        let info = EdnsInfo::scan(&query).expect("OPT should still be found");

        assert!(
            info.cookie.is_none(),
            "invalid COOKIE lengths must not be reflected"
        );
    }

    #[test]
    fn edns_scan_no_panic_on_malformed_additional() {
        // Build a query that claims ARCOUNT=1 but has truncated bytes.
        let mut w = Writer::with_capacity(64);
        Header::new(0x1111)
            .with_rd(true)
            .with_qdcount(1)
            .with_arcount(1)
            .write(&mut w);
        let n: Name = "example.com".parse().unwrap();
        n.write(&mut w);
        w.write_u16(1u16);
        w.write_u16(1u16);
        // Partial OPT record — truncated after owner byte.
        w.write_u8(0x00); // root owner
        // intentionally missing TYPE/CLASS/TTL/RDLENGTH → scan must return None
        let raw = w.finish();
        let query = Query::try_from(raw).unwrap();
        // Must not panic.
        let result = EdnsInfo::scan(&query);
        assert!(result.is_none());
    }

    #[test]
    fn edns_scan_no_panic_on_all_zeros_additional() {
        // Header says ARCOUNT=5 but additional section is all zeros.
        let mut w = Writer::with_capacity(64);
        Header::new(0x2222)
            .with_rd(true)
            .with_qdcount(1)
            .with_arcount(5)
            .write(&mut w);
        let n: Name = "example.com".parse().unwrap();
        n.write(&mut w);
        w.write_u16(1u16);
        w.write_u16(1u16);
        // Pad with zeros (malformed RR data).
        w.write_slice(&[0u8; 20]);
        let raw = w.finish();
        let query = Query::try_from(raw).unwrap();
        let _ = EdnsInfo::scan(&query); // must not panic
    }

    // ── Block: NxDomain mode ──────────────────────────────────────────────────

    #[test]
    fn block_nxdomain_a_query() {
        let raw = build_query(0xABCD, true, "ads.example.com", 1);
        let query = Query::try_from(raw).unwrap();
        let resp = Response::block(&query, &BlockMode::NxDomain, 60, None);

        let hdr = parse_response_header(&resp);
        assert!(hdr.qr(), "QR must be set");
        assert_eq!(hdr.id, 0xABCD, "ID must match");
        assert!(hdr.rd(), "RD must be copied");
        assert!(hdr.ra(), "RA must be set");
        assert_eq!(hdr.rcode(), Rcode::NxDomain);
        assert_eq!(hdr.qdcount, 1, "QDCOUNT must be 1");
        assert_eq!(hdr.ancount, 0, "ANCOUNT must be 0 for NXDOMAIN");
        assert_eq!(hdr.arcount, 0, "ARCOUNT must be 0 (no EDNS)");
    }

    #[test]
    fn block_nxdomain_any_qtype() {
        // NXDOMAIN for MX (qtype 15).
        let raw = build_query(0x1111, false, "blocked.example", 15);
        let query = Query::try_from(raw).unwrap();
        let resp = Response::block(&query, &BlockMode::NxDomain, 60, None);
        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.rcode(), Rcode::NxDomain);
        assert_eq!(hdr.ancount, 0);
    }

    // ── Block: Address mode — A query ─────────────────────────────────────────

    #[test]
    fn block_address_a_query_returns_configured_ip() {
        let v4 = Ipv4Addr::new(127, 0, 0, 1);
        let v6 = Ipv6Addr::UNSPECIFIED;
        let mode = BlockMode::Address { v4, v6 };
        let raw = build_query(0x1234, true, "blocked.example.com", 1);
        let query = Query::try_from(raw).unwrap();
        let resp = Response::block(&query, &mode, 300, None);

        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.rcode(), Rcode::NoError);
        assert_eq!(hdr.ancount, 1);

        let (rtype, class, ttl, rdata) = read_first_answer(&resp);
        assert_eq!(rtype, 1, "TYPE A");
        assert_eq!(class, 1, "CLASS IN");
        assert_eq!(ttl, 300);
        assert_eq!(&rdata[..], &v4.octets());
    }

    #[test]
    fn block_null_ip_a_query() {
        let mode = BlockMode::null_ip();
        let raw = build_query(0x2345, false, "tracker.example", 1);
        let query = Query::try_from(raw).unwrap();
        let resp = Response::block(&query, &mode, 60, None);

        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.rcode(), Rcode::NoError);
        assert_eq!(hdr.ancount, 1);

        let (rtype, _, ttl, rdata) = read_first_answer(&resp);
        assert_eq!(rtype, 1);
        assert_eq!(ttl, 60);
        assert_eq!(&rdata[..], &[0u8, 0, 0, 0]); // 0.0.0.0
    }

    // ── Block: Address mode — AAAA query ─────────────────────────────────────

    #[test]
    fn block_address_aaaa_query_returns_configured_ip() {
        let v4 = Ipv4Addr::UNSPECIFIED;
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mode = BlockMode::Address { v4, v6 };
        let raw = build_query(0x5678, true, "blocked.example.com", 28);
        let query = Query::try_from(raw).unwrap();
        let resp = Response::block(&query, &mode, 120, None);

        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.rcode(), Rcode::NoError);
        assert_eq!(hdr.ancount, 1);

        let (rtype, class, ttl, rdata) = read_first_answer(&resp);
        assert_eq!(rtype, 28, "TYPE AAAA");
        assert_eq!(class, 1, "CLASS IN");
        assert_eq!(ttl, 120);
        assert_eq!(&rdata[..], &v6.octets());
    }

    #[test]
    fn block_null_ip_aaaa_query() {
        let mode = BlockMode::null_ip();
        let raw = build_query(0x3456, false, "tracker.example", 28);
        let query = Query::try_from(raw).unwrap();
        let resp = Response::block(&query, &mode, 60, None);

        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.rcode(), Rcode::NoError);
        assert_eq!(hdr.ancount, 1);

        let (_, _, _, rdata) = read_first_answer(&resp);
        assert_eq!(&rdata[..], &[0u8; 16]); // ::
    }

    // ── Block: Address mode — other qtype → NODATA ────────────────────────────

    #[test]
    fn block_address_mx_qtype_is_nodata() {
        let mode = BlockMode::null_ip();
        let raw = build_query(0x4567, true, "blocked.example", 15); // MX = 15
        let query = Query::try_from(raw).unwrap();
        let resp = Response::block(&query, &mode, 60, None);

        let hdr = parse_response_header(&resp);
        assert_eq!(
            hdr.rcode(),
            Rcode::NoError,
            "Address mode non-A/AAAA → NODATA"
        );
        assert_eq!(hdr.ancount, 0, "NODATA must have 0 answers");
    }

    #[test]
    fn block_address_txt_qtype_is_nodata() {
        let mode = BlockMode::null_ip();
        let raw = build_query(0x5678, false, "blocked.example", 16); // TXT = 16
        let query = Query::try_from(raw).unwrap();
        let resp = Response::block(&query, &mode, 60, None);
        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.rcode(), Rcode::NoError);
        assert_eq!(hdr.ancount, 0);
    }

    #[test]
    fn block_nxdomain_mx_qtype() {
        let raw = build_query(0x6789, false, "blocked.example", 15);
        let query = Query::try_from(raw).unwrap();
        let resp = Response::block(&query, &BlockMode::NxDomain, 60, None);
        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.rcode(), Rcode::NxDomain);
        assert_eq!(hdr.ancount, 0);
    }

    // ── Local records ─────────────────────────────────────────────────────────

    #[test]
    fn local_a_record() {
        let raw = build_query(0xBEEF, true, "local.home", 1);
        let query = Query::try_from(raw).unwrap();
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        let rdata = addr.octets();
        let records = [LocalRecord {
            rtype: 1,
            rdata: &rdata,
        }];
        let resp = Response::local(&query, &records, 3600, None);

        let hdr = parse_response_header(&resp);
        assert!(hdr.aa(), "local response must have AA=1");
        assert_eq!(hdr.rcode(), Rcode::NoError);
        assert_eq!(hdr.ancount, 1);

        let (rtype, _, ttl, rdata_got) = read_first_answer(&resp);
        assert_eq!(rtype, 1);
        assert_eq!(ttl, 3600);
        assert_eq!(&rdata_got[..], &addr.octets());
    }

    #[test]
    fn local_aaaa_record() {
        let raw = build_query(0xCAFE, true, "local.home", 28);
        let query = Query::try_from(raw).unwrap();
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        let rdata = addr.octets();
        let records = [LocalRecord {
            rtype: 28,
            rdata: &rdata,
        }];
        let resp = Response::local(&query, &records, 3600, None);

        let hdr = parse_response_header(&resp);
        assert!(hdr.aa());
        assert_eq!(hdr.ancount, 1);

        let (rtype, _, _, rdata_got) = read_first_answer(&resp);
        assert_eq!(rtype, 28);
        assert_eq!(&rdata_got[..], &addr.octets());
    }

    #[test]
    fn local_nodata_authoritative() {
        // AAAA query but only an A record exists (caller decides, we just call nodata).
        let raw = build_query(0xDEAD, true, "local.home", 28);
        let query = Query::try_from(raw).unwrap();
        let resp = Response::local_nodata(&query, None);

        let hdr = parse_response_header(&resp);
        assert!(hdr.aa(), "NODATA must be authoritative");
        assert_eq!(hdr.rcode(), Rcode::NoError);
        assert_eq!(hdr.ancount, 0);
    }

    #[test]
    fn local_ptr_answer_carries_name_rdata() {
        // A PTR query for 192.168.1.1's reverse name.
        let raw = build_query(0x4242, true, "1.1.168.192.in-addr.arpa", 12);
        let query = Query::try_from(raw).unwrap();
        let target: Name = "router.home.lan".parse().unwrap();

        let resp = Response::local_ptr(&query, &target, 300, None);

        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.id, 0x4242);
        assert!(hdr.aa(), "PTR answer must be authoritative");
        assert_eq!(hdr.rcode(), Rcode::NoError);
        assert_eq!(hdr.ancount, 1);

        let (rtype, class, ttl, rdata) = read_first_answer(&resp);
        assert_eq!(rtype, 12, "PTR type");
        assert_eq!(class, CLASS_IN, "IN class");
        assert_eq!(ttl, 300);

        // RDATA is the uncompressed target name; decode it back.
        let mut rr = Reader::new(rdata);
        let decoded = Name::read_question(&mut rr).expect("PTR rdata is a valid name");
        assert_eq!(decoded, target, "RDATA must encode the PTR target name");
    }

    // ── Error responses ───────────────────────────────────────────────────────

    #[test]
    fn error_response_servfail() {
        let raw = build_query(0xF00D, true, "fail.example.com", 1);
        let query = Query::try_from(raw).unwrap();
        let resp = Response::error_response(&query, Rcode::ServFail, None);

        let hdr = parse_response_header(&resp);
        assert!(hdr.qr());
        assert_eq!(hdr.id, 0xF00D);
        assert!(hdr.rd(), "RD must be copied");
        assert!(hdr.ra(), "RA must be set");
        assert_eq!(hdr.rcode(), Rcode::ServFail);
        assert_eq!(hdr.qdcount, 1);
        assert_eq!(hdr.ancount, 0);
    }

    #[test]
    fn error_response_refused() {
        let raw = build_query(0x1111, false, "example.com", 1);
        let query = Query::try_from(raw).unwrap();
        let resp = Response::error_response(&query, Rcode::Refused, None);

        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.rcode(), Rcode::Refused);
        assert!(!hdr.rd(), "RD=0 copied from query");
        assert_eq!(hdr.id, 0x1111);
    }

    #[test]
    fn formerr_id_only() {
        let resp = Response::formerr(0xDEAD);
        let hdr = parse_response_header(&resp);

        assert!(hdr.qr(), "QR must be set");
        assert_eq!(hdr.id, 0xDEAD, "ID must match");
        assert_eq!(hdr.rcode(), Rcode::FormErr);
        assert_eq!(hdr.qdcount, 0, "FORMERR from id has no question");
        assert_eq!(hdr.ancount, 0);
        assert_eq!(hdr.arcount, 0);
        assert!(!hdr.rd(), "RD must be 0 (no query to copy from)");
        assert!(!hdr.ra(), "RA must be 0 for FORMERR-from-id");
    }

    #[test]
    fn formerr_minimum_length() {
        let resp = Response::formerr(0x0000);
        // A FORMERR with no question is just the 12-byte header.
        assert_eq!(resp.len(), 12, "FORMERR from id must be exactly 12 bytes");
    }

    // ── Question wire raw-copy / DNS 0x20 case preservation ───────────────────

    #[test]
    fn question_wire_bytes_preserved_exactly() {
        // Build a query with mixed-case label bytes by hand so the QNAME on the
        // wire is "eXaMpLe.CoM." (the normalized Name will be "example.com."
        // but the wire bytes must be preserved verbatim in the response).
        let mut w = Writer::with_capacity(64);
        Header::new(0xABCD)
            .with_rd(true)
            .with_qdcount(1)
            .write(&mut w);
        // Write the name manually with mixed case to bypass normalization.
        // \x07 eXaMpLe \x03 CoM \x00
        w.write_u8(7);
        w.write_slice(b"eXaMpLe");
        w.write_u8(3);
        w.write_slice(b"CoM");
        w.write_u8(0);
        w.write_u16(1u16); // QTYPE A
        w.write_u16(1u16); // QCLASS IN
        let raw = w.finish();

        let query = Query::try_from(raw.clone()).unwrap();

        // Extract the question bytes from the original query.
        let question_start = 12usize;
        let question_end = query.question_end();
        let original_question_bytes = &raw[question_start..question_end];

        // Synthesize a block response.
        let mode = BlockMode::null_ip();
        let resp = Response::block(&query, &mode, 60, None);

        // Extract the question bytes from the response.
        let resp_question_bytes = &resp[question_start..question_end];

        // They must be byte-identical (0x20 case preserved).
        assert_eq!(
            resp_question_bytes, original_question_bytes,
            "question bytes in response must be byte-identical to query question bytes \
             (DNS 0x20 case preservation)"
        );
    }

    // ── EDNS echo: OPT reflected in response ──────────────────────────────────

    #[test]
    fn edns_query_without_cookie_gets_opt_in_response() {
        let raw = build_query_with_opt(0x9999, true, "blocked.example.com", 1, 4096, None);
        let query = Query::try_from(raw).unwrap();
        let edns = EdnsInfo::scan(&query).expect("OPT must be found");

        let resp = Response::block(&query, &BlockMode::null_ip(), 60, Some(&edns));

        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.arcount, 1, "ARCOUNT must be 1 with EDNS echo");

        let (rtype, class, ttl, rdata) = read_opt_rr(&resp).expect("OPT must be in response");
        assert_eq!(rtype, OPT_TYPE, "TYPE must be OPT (41)");
        assert_eq!(
            class, SERVER_UDP_PAYLOAD_SIZE,
            "CLASS must be server UDP payload size"
        );
        assert_eq!(ttl, 0, "OPT TTL must be 0");
        assert_eq!(
            rdata.len(),
            0,
            "no COOKIE in response when query had no cookie"
        );
    }

    #[test]
    fn edns_query_with_cookie_reflected_in_response() {
        let client_cookie: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let raw = build_query_with_opt(
            0xAAAA,
            true,
            "blocked.example.com",
            1,
            1232,
            Some(client_cookie),
        );
        let query = Query::try_from(raw).unwrap();
        let edns = EdnsInfo::scan(&query).expect("OPT must be found");

        let resp = Response::block(&query, &BlockMode::null_ip(), 60, Some(&edns));

        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.arcount, 1);

        let (_, _, _, opt_rdata) = read_opt_rr(&resp).expect("OPT must be in response");
        // RDATA should contain: option-code(2) + option-length(2) + cookie bytes.
        assert!(opt_rdata.len() >= 4 + client_cookie.len());

        let opt_code = u16::from_be_bytes([opt_rdata[0], opt_rdata[1]]);
        let opt_len = u16::from_be_bytes([opt_rdata[2], opt_rdata[3]]) as usize;
        let opt_data = &opt_rdata[4..4 + opt_len];

        assert_eq!(
            opt_code, EDNS_OPTION_COOKIE,
            "OPTION-CODE must be 10 (COOKIE)"
        );
        assert_eq!(opt_data, client_cookie, "cookie must be reflected verbatim");
    }

    #[test]
    fn edns_query_with_invalid_cookie_omits_cookie_from_response() {
        let invalid_cookie = [0xAA; 9];
        let raw = build_query_with_opt(
            0xAAAB,
            true,
            "blocked.example.com",
            1,
            1232,
            Some(&invalid_cookie),
        );
        let query = Query::try_from(raw).unwrap();
        let edns = EdnsInfo::scan(&query).expect("OPT must be found");

        let resp = Response::block(&query, &BlockMode::null_ip(), 60, Some(&edns));
        let (_, _, _, opt_rdata) = read_opt_rr(&resp).expect("OPT must be in response");

        assert!(
            opt_rdata.is_empty(),
            "invalid COOKIE option data must not be reflected"
        );
    }

    #[test]
    fn non_edns_query_has_no_opt_in_response() {
        let raw = build_query(0xBBBB, true, "blocked.example.com", 1);
        let query = Query::try_from(raw).unwrap();
        // No EDNS.
        let resp = Response::block(&query, &BlockMode::null_ip(), 60, None);

        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.arcount, 0, "no EDNS in query → no OPT in response");
        assert!(read_opt_rr(&resp).is_none());
    }

    // ── EDNS with block NxDomain ──────────────────────────────────────────────

    #[test]
    fn edns_block_nxdomain_includes_opt() {
        let raw = build_query_with_opt(0xCCCC, true, "blocked.example", 1, 512, None);
        let query = Query::try_from(raw).unwrap();
        let edns = EdnsInfo::scan(&query).unwrap();
        let resp = Response::block(&query, &BlockMode::NxDomain, 60, Some(&edns));

        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.rcode(), Rcode::NxDomain);
        assert_eq!(hdr.arcount, 1);
        assert!(read_opt_rr(&resp).is_some());
    }

    // ── EDNS with error response ──────────────────────────────────────────────

    #[test]
    fn edns_servfail_includes_opt() {
        let raw = build_query_with_opt(0xDDDD, true, "fail.example", 1, 1232, None);
        let query = Query::try_from(raw).unwrap();
        let edns = EdnsInfo::scan(&query).unwrap();
        let resp = Response::error_response(&query, Rcode::ServFail, Some(&edns));

        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.rcode(), Rcode::ServFail);
        assert_eq!(hdr.arcount, 1);
        assert!(read_opt_rr(&resp).is_some());
    }

    // ── Header flags correctness ──────────────────────────────────────────────

    #[test]
    fn block_response_copies_rd_flag() {
        // Query with RD=1.
        let raw_rd1 = build_query(0x1234, true, "example.com", 1);
        let q1 = Query::try_from(raw_rd1).unwrap();
        let resp1 = Response::block(&q1, &BlockMode::null_ip(), 60, None);
        assert!(
            parse_response_header(&resp1).rd(),
            "RD must be copied (RD=1)"
        );

        // Query with RD=0.
        let raw_rd0 = build_query(0x5678, false, "example.com", 1);
        let q0 = Query::try_from(raw_rd0).unwrap();
        let resp0 = Response::block(&q0, &BlockMode::null_ip(), 60, None);
        assert!(
            !parse_response_header(&resp0).rd(),
            "RD must be copied (RD=0)"
        );
    }

    #[test]
    fn block_response_always_sets_qr_and_ra() {
        let raw = build_query(0x9999, false, "example.com", 1);
        let query = Query::try_from(raw).unwrap();
        let resp = Response::block(&query, &BlockMode::NxDomain, 60, None);
        let hdr = parse_response_header(&resp);
        assert!(hdr.qr(), "QR must be 1");
        assert!(hdr.ra(), "RA must be 1");
    }

    #[test]
    fn local_response_sets_aa_flag() {
        let raw = build_query(0xAAAA, true, "local.home", 1);
        let query = Query::try_from(raw).unwrap();
        let rdata = Ipv4Addr::new(10, 0, 0, 1).octets();
        let records = [LocalRecord {
            rtype: 1,
            rdata: &rdata,
        }];
        let resp = Response::local(&query, &records, 60, None);
        assert!(parse_response_header(&resp).aa(), "local must set AA");
    }

    // ── Answer owner is compression pointer ──────────────────────────────────

    #[test]
    fn answer_owner_is_compression_pointer() {
        let mode = BlockMode::null_ip();
        let raw = build_query(0x1234, true, "example.com", 1);
        let query = Query::try_from(raw).unwrap();
        let resp = Response::block(&query, &mode, 60, None);

        // The answer RR owner should be at `question_end` bytes offset.
        let qend = query.question_end();
        assert_eq!(resp[qend], 0xC0, "first byte of owner must be 0xC0");
        assert_eq!(resp[qend + 1], 0x0C, "second byte of owner must be 0x0C");
    }

    // ── Round-trip: parse query → synthesize → re-parse ──────────────────────

    #[test]
    fn round_trip_block_response_is_parseable() {
        let raw = build_query(0x4321, true, "tracker.example.com", 1);
        let query = Query::try_from(raw).unwrap();
        let resp = Response::block(&query, &BlockMode::null_ip(), 300, None);

        // The response should parse as a valid message (it's a response, not a
        // query, so Query::try_from may fail on QR=1 — but header parsing
        // must succeed and the response bytes must be well-formed).
        let hdr = parse_response_header(&resp);
        assert!(hdr.qr());
        assert_eq!(hdr.id, 0x4321);
        assert_eq!(hdr.qdcount, 1);
        assert_eq!(hdr.ancount, 1);
    }

    // ── Truncated response ────────────────────────────────────────────────────

    #[test]
    fn truncated_sets_tc_qr_ra_and_no_answers() {
        let raw = build_query(0xBEEF, true, "example.com", 1);
        let query = Query::try_from(raw).unwrap();
        let resp = Response::truncated(&query, None);

        let hdr = parse_response_header(&resp);
        assert!(hdr.qr(), "QR must be set");
        assert!(hdr.tc(), "TC must be set");
        assert!(hdr.ra(), "RA must be set");
        assert!(hdr.rd(), "RD must be copied from query");
        assert_eq!(hdr.id, 0xBEEF, "ID must match");
        assert_eq!(hdr.rcode(), Rcode::NoError, "RCODE must be NOERROR");
        assert_eq!(hdr.qdcount, 1, "QDCOUNT must be 1");
        assert_eq!(hdr.ancount, 0, "ANCOUNT must be 0");
        assert_eq!(hdr.arcount, 0, "ARCOUNT must be 0 (no EDNS)");
    }

    #[test]
    fn truncated_echoes_question() {
        let raw = build_query(0x1234, false, "truncate.test", 1);
        let query = Query::try_from(raw.clone()).unwrap();
        let resp = Response::truncated(&query, None);

        // Question bytes should be at offset 12 and match the original.
        let question_start = 12usize;
        let question_end = query.question_end();
        assert_eq!(
            &resp[question_start..question_end],
            &raw[question_start..question_end],
            "question section must be echoed verbatim"
        );
    }

    #[test]
    fn truncated_with_edns_includes_opt() {
        let raw = build_query_with_opt(0xCAFE, true, "large.example.com", 1, 4096, None);
        let query = Query::try_from(raw).unwrap();
        let edns = EdnsInfo::scan(&query).expect("OPT must be found");

        let resp = Response::truncated(&query, Some(&edns));

        let hdr = parse_response_header(&resp);
        assert!(hdr.tc(), "TC must be set");
        assert_eq!(hdr.arcount, 1, "ARCOUNT must be 1 with EDNS");
        assert!(read_opt_rr(&resp).is_some(), "OPT must be present");
    }

    // ── NOTIMP ────────────────────────────────────────────────────────────────

    #[test]
    fn notimp_echoes_id_sets_qr_and_rcode() {
        let resp = Response::notimp(0x4242);
        let hdr = parse_response_header(&resp);
        assert_eq!(hdr.id, 0x4242, "id must be echoed");
        assert!(hdr.qr(), "QR must be set on a NOTIMP reply");
        assert_eq!(hdr.rcode(), Rcode::NotImpl, "RCODE must be NOTIMP");
        assert_eq!(hdr.qdcount, 0, "minimal NOTIMP echoes no question");
    }

    // ── BlockMode::null_ip constructor ────────────────────────────────────────

    #[test]
    fn null_ip_returns_unspecified_addresses() {
        match BlockMode::null_ip() {
            BlockMode::Address { v4, v6 } => {
                assert_eq!(v4, Ipv4Addr::UNSPECIFIED);
                assert_eq!(v6, Ipv6Addr::UNSPECIFIED);
            }
            _ => panic!("null_ip must return Address variant"),
        }
    }
}

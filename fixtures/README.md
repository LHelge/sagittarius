# DNS Wire-Format Fixtures

Hand-authored DNS wire-format messages used as:

1. **Unit-test fixtures** — `tests/fixtures.rs` loads each file and asserts
   the expected parse outcome, acting as an independent cross-check of the
   codec (they were not produced by our own `Writer`).
2. **Fuzz seed corpus** — copy this directory as the initial corpus when
   running `cargo fuzz` (see `fuzz/README.md`):
   ```
   cargo +nightly fuzz run parse fixtures/
   ```

All values are big-endian (network byte order) per RFC 1035.

---

## File descriptions

### `a_query.bin` — 29 bytes

Standard A query for `example.com`, `RD=1`.

```
Header:   ID=0x1234, flags=0x0100 (RD=1), QDCOUNT=1
Question: QNAME=example.com (7+example+3+com+0), QTYPE=1 (A), QCLASS=1 (IN)
Hex:      12 34 01 00  00 01 00 00  00 00 00 00
          07 65 78 61  6d 70 6c 65  03 63 6f 6d  00
          00 01  00 01
```

Expected parse: `Query` with `header.id=0x1234`, `question.qtype=A`,
`question.qclass=IN`, `question.name="example.com."`.

---

### `aaaa_query.bin` — 29 bytes

AAAA query for `example.com`, `RD=1`.

```
Header:   ID=0x5678, flags=0x0100 (RD=1), QDCOUNT=1
Question: QNAME=example.com, QTYPE=28 (AAAA), QCLASS=1 (IN)
Hex:      56 78 01 00  00 01 00 00  00 00 00 00
          07 65 78 61  6d 70 6c 65  03 63 6f 6d  00
          00 1c  00 01
```

Expected parse: `Query` with `header.id=0x5678`, `question.qtype=Aaaa`.

---

### `a_response.bin` — 45 bytes

A response for `example.com` with one A answer `93.184.216.34`, TTL 3600.

```
Header:   ID=0x1234, flags=0x8180 (QR=1, RD=1, RA=1), QDCOUNT=1, ANCOUNT=1
Question: QNAME=example.com, QTYPE=A, QCLASS=IN
Answer:   owner=0xC00C (ptr→offset 12), TYPE=1(A), CLASS=1(IN),
          TTL=3600 (0x00000E10), RDLENGTH=4, RDATA=5d:b8:d8:22

TTL field at byte offset 35 (= 12 header + 13 qname + 4 qtype/qclass +
                                2 owner-ptr + 2 type + 2 class).
```

Expected `TtlScan`: `min_ttl=Some(3600)`, 1 offset at byte 35.

---

### `a_response_edns.bin` — 56 bytes

A response carrying an OPT record (EDNS, UDP payload size 4096, no options).

```
Header:   ID=0x9abc, flags=0x8180, QDCOUNT=1, ANCOUNT=1, ARCOUNT=1
Question: QNAME=example.com, QTYPE=A, QCLASS=IN
Answer:   same A record as above (TTL 3600)
Additional: OPT owner=0x00(root), TYPE=41, CLASS=4096, TTL=0, RDLENGTH=0
```

Expected `TtlScan`: `min_ttl=Some(3600)`, 1 offset (OPT excluded).
Expected `EdnsInfo::scan`: when parsed as a `Query`-like structure via
`TtlScan`, the OPT record is skipped from TTL tracking; the query form
(headers set to query) would yield `EdnsInfo { udp_payload_size=4096 }`.

---

### `nxdomain_response.bin` — 122 bytes

NXDOMAIN response for `notexist.example.com`, with a SOA record in the
authority section.

```
Header:   ID=0xdead, flags=0x8583 (QR=1, AA=1, RD=1, RA=1, RCODE=3),
          QDCOUNT=1, NSCOUNT=1
Question: QNAME=notexist.example.com, QTYPE=A, QCLASS=IN
Authority: SOA owner=example.com, TYPE=6, CLASS=IN, TTL=900
           MNAME=ns1.example.com, RNAME=hostmaster.example.com
           serial=2024010101, refresh=3600, retry=900, expire=604800, min=300

SOA TTL field at byte offset 55 (= 12 header + 22 qname + 4 qtype/qclass +
                                   13 soa-owner + 2 type + 2 class).
```

Expected `TtlScan`: `min_ttl=Some(900)`, 1 TTL offset at byte 55.

---

### `multi_rr_response.bin` — 81 bytes

A response for `www.example.com` with 3 A records (round-robin IPs),
each TTL 300. The answer owner names use compression pointers (`0xC0 0x0C`).

```
Header:   ID=0xbeef, flags=0x8180, QDCOUNT=1, ANCOUNT=3
Question: QNAME=www.example.com, QTYPE=A, QCLASS=IN

Answer 1: owner=ptr, TYPE=A, CLASS=IN, TTL=300, RDATA=01:02:03:04
Answer 2: owner=ptr, TYPE=A, CLASS=IN, TTL=300, RDATA=05:06:07:08
Answer 3: owner=ptr, TYPE=A, CLASS=IN, TTL=300, RDATA=09:0a:0b:0c

TTL offsets: 39, 55, 71 (each spaced 16 bytes = 2+2+2+4+2+4 bytes per RR,
question ends at offset 33 = 12 header + 17 qname + 4 qtype/qclass).
```

Expected `TtlScan`: `min_ttl=Some(300)`, 3 offsets at `[39, 55, 71]`.

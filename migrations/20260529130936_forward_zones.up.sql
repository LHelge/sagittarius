-- E13.3: conditional-forward zones.
--
-- A general suffix → target routing table: a query whose name falls under an
-- enabled `zone_suffix` is forwarded to that zone's `target` resolver instead
-- of the default upstream pool (E13.4).  Seeded with the RFC1918 / ULA reverse
-- zones so the admin can point LAN reverse-DNS (PTR) at the router/DHCP, but the
-- mechanism is not PTR-specific — it later serves split-horizon forward zones
-- (e.g. corp.internal) too.

CREATE TABLE forward_zones (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    zone_suffix TEXT    NOT NULL UNIQUE,   -- e.g. '168.192.in-addr.arpa'
    target      TEXT,                       -- resolver IP or IP:port; NULL until set
    enabled     INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    sort_order  INTEGER NOT NULL DEFAULT 0
);

-- Speed up the hot-path load of all enabled zones in order.
CREATE INDEX idx_forward_zones_enabled_sort ON forward_zones (enabled, sort_order);

-- ── Seed the private reverse zones ────────────────────────────────────────────
-- All disabled with a NULL target: the admin enables the ones they want and
-- sets the router/DHCP resolver address.  ON CONFLICT keeps re-application a
-- no-op and never clobbers admin edits.
--
--   10.0.0.0/8      → 10.in-addr.arpa
--   172.16.0.0/12   → 16.172.in-addr.arpa … 31.172.in-addr.arpa
--   192.168.0.0/16  → 168.192.in-addr.arpa
--   fc00::/7 (ULA)  → c.f.ip6.arpa, d.f.ip6.arpa

INSERT INTO forward_zones (zone_suffix, target, enabled, sort_order) VALUES
    ('10.in-addr.arpa',      NULL, 0,  0),
    ('168.192.in-addr.arpa', NULL, 0,  1),
    ('16.172.in-addr.arpa',  NULL, 0,  2),
    ('17.172.in-addr.arpa',  NULL, 0,  3),
    ('18.172.in-addr.arpa',  NULL, 0,  4),
    ('19.172.in-addr.arpa',  NULL, 0,  5),
    ('20.172.in-addr.arpa',  NULL, 0,  6),
    ('21.172.in-addr.arpa',  NULL, 0,  7),
    ('22.172.in-addr.arpa',  NULL, 0,  8),
    ('23.172.in-addr.arpa',  NULL, 0,  9),
    ('24.172.in-addr.arpa',  NULL, 0, 10),
    ('25.172.in-addr.arpa',  NULL, 0, 11),
    ('26.172.in-addr.arpa',  NULL, 0, 12),
    ('27.172.in-addr.arpa',  NULL, 0, 13),
    ('28.172.in-addr.arpa',  NULL, 0, 14),
    ('29.172.in-addr.arpa',  NULL, 0, 15),
    ('30.172.in-addr.arpa',  NULL, 0, 16),
    ('31.172.in-addr.arpa',  NULL, 0, 17),
    ('c.f.ip6.arpa',         NULL, 0, 18),
    ('d.f.ip6.arpa',         NULL, 0, 19)
ON CONFLICT(zone_suffix) DO NOTHING;

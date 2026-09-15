// db.c — see db.h. sqlite projection of SmState + sync/reorg/oracle bookkeeping.
#include "db.h"
#include "indexer.h"        // IDX_DNET_MARK — the overlay bucket's agent prefix
#include "oracle_feed.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>      // inet_pton — idx_db_peers_scrub's numeric test

static const char *SCHEMA =
    "PRAGMA journal_mode=WAL;"
    "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);"
    // bits: the header's compact target, the Digishield retarget context
    // (0 on rows written before the column existed — validation grace)
    "CREATE TABLE IF NOT EXISTS blocks(height INTEGER PRIMARY KEY, hash BLOB, time INTEGER, coinbase INTEGER, bytes INTEGER, bits INTEGER DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS names(name TEXT PRIMARY KEY, owner BLOB, owner_type INT, lease_expiry INT, st INT,"
    "  seller BLOB, seller_type INT, price INT, offer_expiry INT, buyer BLOB, burn_leg INT, pay_leg INT, reserve_expiry INT);"
    "CREATE TABLE IF NOT EXISTS commits(commitment BLOB, commit_height INT, tx_index INT, commit_time INT);"
    "CREATE TABLE IF NOT EXISTS muts(owner BLOB PRIMARY KEY, height INT);"
    "CREATE TABLE IF NOT EXISTS raw_blocks(height INTEGER PRIMARY KEY, raw BLOB);"
    // ownership history: one row per ownership CHANGE (owner NULL = lapse). The
    // epoch substrate for overlay layers; see db.h.
    "CREATE TABLE IF NOT EXISTS epochs(name TEXT, start_height INTEGER, owner BLOB, owner_type INT,"
    "  PRIMARY KEY(name, start_height));"
    "CREATE TABLE IF NOT EXISTS watch(h160 BLOB PRIMARY KEY);"
    "CREATE TABLE IF NOT EXISTS utxos(txid BLOB, vout INTEGER, h160 BLOB, value INTEGER,"
    "  height INTEGER, spent_height INTEGER, PRIMARY KEY(txid, vout));"
    // chain peers harvested from addr gossip: sync-failover pool + crawl frontier.
    // last_good = last completed handshake by US (0 = only ever heard of);
    // last_try = last dial attempt (crawl politeness); agent = subver captured at
    // the last good handshake ("/pepenet-…" = dns-aware, the mesh bucket).
    // dnet = 1 when some pepenet peer vouched for this addr over dnaddr (an
    // overlay-discovery hint we can act on BEFORE our own handshake confirms the
    // agent — this is what lets the dns mesh find itself on the host chain).
    "CREATE TABLE IF NOT EXISTS peers(addr TEXT PRIMARY KEY, services INTEGER,"
    "  last_seen INTEGER, last_good INTEGER DEFAULT 0,"
    "  last_try INTEGER DEFAULT 0, agent TEXT DEFAULT '', dnet INTEGER DEFAULT 0);"
    "CREATE INDEX IF NOT EXISTS names_owner ON names(owner);"
    "CREATE INDEX IF NOT EXISTS blocks_hash ON blocks(hash);";

sqlite3 *idx_db_open(const char *path) {
    sqlite3 *db; if (sqlite3_open(path, &db) != SQLITE_OK) return NULL;
    // Multiple connections share one db (desktop client: sync thread + UI
    // reader; CLI: digest/resolve against a live sync) — wait out transient
    // locks instead of failing the open or a mid-sync write.
    sqlite3_busy_timeout(db, 5000);
    char *err = NULL; if (sqlite3_exec(db, SCHEMA, NULL, NULL, &err) != SQLITE_OK) { fprintf(stderr, "db schema: %s\n", err ? err : "?"); sqlite3_free(err); sqlite3_close(db); return NULL; }
    // columns added after the peers table first shipped — best-effort migration
    // (the error on an already-migrated db is expected and ignored)
    sqlite3_exec(db, "ALTER TABLE peers ADD COLUMN last_try INTEGER DEFAULT 0", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE peers ADD COLUMN agent TEXT DEFAULT ''", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE peers ADD COLUMN dnet INTEGER DEFAULT 0", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE blocks ADD COLUMN bits INTEGER DEFAULT 0", NULL, NULL, NULL);
    return db;
}
void idx_db_close(sqlite3 *db) { if (db) sqlite3_close(db); }

static int meta_set(sqlite3 *db, const char *k, const char *v) {
    sqlite3_stmt *st; if (sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, k, -1, SQLITE_STATIC); sqlite3_bind_text(st, 2, v, -1, SQLITE_STATIC);
    int ok = sqlite3_step(st) == SQLITE_DONE; sqlite3_finalize(st); return ok;
}
static int meta_get(sqlite3 *db, const char *k, char *out, int n) {
    sqlite3_stmt *st; sqlite3_prepare_v2(db, "SELECT v FROM meta WHERE k=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, k, -1, SQLITE_STATIC); int found = 0;
    if (sqlite3_step(st) == SQLITE_ROW) { snprintf(out, (size_t)n, "%s", sqlite3_column_text(st, 0)); found = 1; }
    sqlite3_finalize(st); return found;
}

static void tohex(const uint8_t *b, int n, char *out) { static const char *H = "0123456789abcdef"; for (int i = 0; i < n; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; } out[2*n] = 0; }

void idx_db_save_sync(sqlite3 *db, int64_t height, const uint8_t tip_hash[32]) {
    char hbuf[32]; snprintf(hbuf, sizeof hbuf, "%lld", (long long)height); meta_set(db, "height", hbuf);
    char hh[65]; tohex(tip_hash, 32, hh); meta_set(db, "tip", hh);
}
void idx_db_set_peer_height(sqlite3 *db, int64_t h) {
    if (h <= 0) return;
    char b[32]; snprintf(b, sizeof b, "%lld", (long long)h);
    meta_set(db, "peer_height", b);
}
int64_t idx_db_get_peer_height(sqlite3 *db) {
    char b[32]; return meta_get(db, "peer_height", b, sizeof b) ? strtoll(b, NULL, 10) : 0;
}
int idx_db_load_sync(sqlite3 *db, int64_t *height, uint8_t tip_hash[32]) {
    char hbuf[32]; if (!meta_get(db, "height", hbuf, sizeof hbuf)) return 0;
    *height = strtoll(hbuf, NULL, 10);
    char hh[80]; if (meta_get(db, "tip", hh, sizeof hh) && strlen(hh) == 64)
        for (int i = 0; i < 32; i++) { unsigned v; sscanf(hh + 2*i, "%2x", &v); tip_hash[i] = (uint8_t)v; }
    return 1;
}
void idx_db_set_activation(sqlite3 *db, int64_t a) { char b[32]; snprintf(b, sizeof b, "%lld", (long long)a); meta_set(db, "activation", b); }
int64_t idx_db_get_activation(sqlite3 *db, int64_t dflt) { char b[32]; return meta_get(db, "activation", b, sizeof b) ? strtoll(b, NULL, 10) : dflt; }
// §3.4 subsidy pinned per db (like activation): sync writes the host profile's value
// so a later refold/digest on this db uses the same subsidy, even for a non-default chain.
void idx_db_set_subsidy(sqlite3 *db, int64_t s) { char b[32]; snprintf(b, sizeof b, "%lld", (long long)s); meta_set(db, "subsidy", b); }
int64_t idx_db_get_subsidy(sqlite3 *db, int64_t dflt) { char b[32]; return meta_get(db, "subsidy", b, sizeof b) ? strtoll(b, NULL, 10) : dflt; }
// one-shot markers in meta (migrations/repairs that must run once per db)
int  idx_db_flag_get(sqlite3 *db, const char *k) { char b[8]; return meta_get(db, k, b, sizeof b); }
void idx_db_flag_set(sqlite3 *db, const char *k) { meta_set(db, k, "1"); }

// ── harvested chain peers (see peers table note in SCHEMA) ────────────────────
void idx_db_peer_note(sqlite3 *db, const char *addr, int64_t services, int64_t now) {
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO peers(addr,services,last_seen) VALUES(?,?,?)"
            " ON CONFLICT(addr) DO UPDATE SET services=excluded.services,"
            "  last_seen=excluded.last_seen", -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_text(st, 1, addr, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, services); sqlite3_bind_int64(st, 3, now);
    sqlite3_step(st); sqlite3_finalize(st);
}
void idx_db_peer_seen(sqlite3 *db, const char *addr, int64_t services,
                      const char *agent, int64_t now) {
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO peers(addr,services,last_seen,last_good,last_try,agent)"
            " VALUES(?,?,?,?,?,?)"
            " ON CONFLICT(addr) DO UPDATE SET services=excluded.services,"
            "  last_seen=excluded.last_seen, last_good=excluded.last_good,"
            "  last_try=excluded.last_try, agent=excluded.agent", -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_text(st, 1, addr, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, services); sqlite3_bind_int64(st, 3, now);
    sqlite3_bind_int64(st, 4, now); sqlite3_bind_int64(st, 5, now);
    sqlite3_bind_text(st, 6, agent ? agent : "", -1, SQLITE_STATIC);
    sqlite3_step(st); sqlite3_finalize(st);
}
void idx_db_peer_bad(sqlite3 *db, const char *addr) {
    // served an invalid block: drop its proven status so the ladder stops
    // preferring it (the addr stays known — it may be an honest node on a
    // garbage fork rather than an attacker)
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, "UPDATE peers SET last_good=0 WHERE addr=?", -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_text(st, 1, addr, -1, SQLITE_STATIC);
    sqlite3_step(st); sqlite3_finalize(st);
}
void idx_db_peer_tried(sqlite3 *db, const char *addr, int64_t now) {
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO peers(addr,services,last_seen,last_try) VALUES(?,0,?,?)"
            " ON CONFLICT(addr) DO UPDATE SET last_try=excluded.last_try",
            -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_text(st, 1, addr, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, now); sqlite3_bind_int64(st, 3, now);
    sqlite3_step(st); sqlite3_finalize(st);
}
// Boot-time hygiene: the addr book is numeric BY CONSTRUCTION now (the serve
// loop records the resolved net_peer_str, never the dial-target text) — but
// hostname rows written by pre-fix builds ride the 14-day TTL, and every
// name-blind string dedup then double-dials the machine the hostname resolves
// to. Nothing can write such a row anymore; delete any that remain.
void idx_db_peers_scrub(sqlite3 *db) {
    sqlite3_stmt *st;
    char stale[64][80]; int n = 0;
    if (sqlite3_prepare_v2(db, "SELECT addr FROM peers", -1, &st, NULL) != SQLITE_OK) return;
    while (sqlite3_step(st) == SQLITE_ROW && n < 64) {
        const char *a = (const char *)sqlite3_column_text(st, 0);
        if (!a) continue;
        char host[80]; snprintf(host, sizeof host, "%s", a);
        char *col = strrchr(host, ':'); if (col) *col = 0;
        struct in_addr a4; struct in6_addr a6;
        if (inet_pton(AF_INET, host, &a4) != 1 && inet_pton(AF_INET6, host, &a6) != 1)
            snprintf(stale[n++], sizeof stale[0], "%s", a);
    }
    sqlite3_finalize(st);
    for (int i = 0; i < n; i++) {
        if (sqlite3_prepare_v2(db, "DELETE FROM peers WHERE addr=?", -1, &st, NULL) != SQLITE_OK)
            return;
        sqlite3_bind_text(st, 1, stale[i], -1, SQLITE_STATIC);
        sqlite3_step(st); sqlite3_finalize(st);
        fprintf(stderr, "db: purged non-numeric peer row %s (pre-fix relic)\n", stale[i]);
    }
}
int idx_db_peers_crawl(sqlite3 *db, char (*out)[80], int max) {
    // the crawl frontier: never-tried first, then stalest-tried, freshest
    // sighting as the tiebreak — exploration over re-poking dead addrs
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
            "SELECT addr FROM peers ORDER BY last_try ASC, last_seen DESC LIMIT ?",
            -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(st, 1, max);
    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW)
        snprintf(out[n++], 80, "%s", sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    return n;
}
int idx_db_peers_rows(sqlite3 *db, IdxPeerRow *out, int max) {
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
            "SELECT addr,services,last_seen FROM peers WHERE last_seen>0"
            " ORDER BY last_seen DESC LIMIT ?", -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(st, 1, max);
    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW) {
        snprintf(out[n].addr, sizeof out[n].addr, "%s", sqlite3_column_text(st, 0));
        out[n].services = sqlite3_column_int64(st, 1);
        out[n].last_seen = sqlite3_column_int64(st, 2);
        n++;
    }
    sqlite3_finalize(st);
    return n;
}
int idx_db_peers_select(sqlite3 *db, IdxPeerSel *out, int max, int tried) {
    sqlite3_stmt *st;
    const char *sql = tried
        ? "SELECT addr,last_good,last_try FROM peers WHERE last_good>0"
          " ORDER BY last_good DESC LIMIT ?"
        : "SELECT addr,last_good,last_try FROM peers WHERE last_good=0"
          " AND (services&1)!=0 ORDER BY RANDOM() LIMIT ?";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(st, 1, max);
    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW) {
        snprintf(out[n].addr, sizeof out[n].addr, "%s", sqlite3_column_text(st, 0));
        out[n].last_good = sqlite3_column_int64(st, 1);
        out[n].last_try = sqlite3_column_int64(st, 2);
        n++;
    }
    sqlite3_finalize(st);
    return n;
}
int idx_db_peers_agent(sqlite3 *db, const char *prefix, char (*out)[80], int max) {
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
            "SELECT addr FROM peers WHERE agent LIKE ?||'%' ORDER BY last_good DESC LIMIT ?",
            -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, prefix, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, max);
    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW)
        snprintf(out[n++], 80, "%s", sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    return n;
}
void idx_db_peer_dnet_note(sqlite3 *db, const char *addr, int64_t services, int64_t now) {
    // learned from a dnaddr gossip: a pepenet peer vouched for this addr. Set the
    // dnet hint + last_seen; never clears agent/last_good (a real handshake still
    // overwrites the truth). This is the row the mesh dialer re-seats from.
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO peers(addr,services,last_seen,dnet) VALUES(?,?,?,1)"
            " ON CONFLICT(addr) DO UPDATE SET last_seen=excluded.last_seen, dnet=1,"
            "  services=CASE WHEN excluded.services!=0 THEN excluded.services ELSE peers.services END",
            -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_text(st, 1, addr, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, services); sqlite3_bind_int64(st, 3, now);
    sqlite3_step(st); sqlite3_finalize(st);
}
int idx_db_peers_dnet(sqlite3 *db, char (*out)[80], int max, int64_t retry_cut) {
    // the overlay dial pool: peers we handshaked as marked (IDX_DNET_MARK
    // agent prefix) OR that a marked peer vouched for (dnet=1). Confirmed-agent
    // first (freshest handshake), then vouched hints by sighting recency — so a
    // node that ran before re-embeds into the mesh from its own memory at startup.
    // retry_cut > 0 = the dialer's failure backoff: skip rows whose last dial
    // failed (last_try > last_good) after the cutoff. 0 = no filter — the dnaddr
    // gossip answer vouches for peers regardless of our own dial luck (they may
    // be reachable from where the asker sits even if not from here).
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
            "SELECT addr FROM peers WHERE (dnet=1 OR agent LIKE '" IDX_DNET_MARK "%')"
            " AND NOT (?2 > 0 AND last_try > last_good AND last_try > ?2)"
            " ORDER BY (agent LIKE '" IDX_DNET_MARK "%') DESC, last_good DESC, last_seen DESC LIMIT ?1",
            -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(st, 1, max);
    sqlite3_bind_int64(st, 2, retry_cut);
    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW)
        snprintf(out[n++], 80, "%s", sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    return n;
}
int idx_db_peers_best(sqlite3 *db, char (*out)[80], int max) {
    // proven peers first (freshest handshake), then harvested block-servers
    // (services bit0 = NODE_NETWORK) by sighting recency
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
            "SELECT addr FROM peers WHERE last_good>0 OR (services&1)!=0"
            " ORDER BY (last_good>0) DESC, last_good DESC, last_seen DESC LIMIT ?",
            -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(st, 1, max);
    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW)
        snprintf(out[n++], 80, "%s", sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    return n;
}

void idx_db_peers_prune(sqlite3 *db, int64_t now, int64_t ttl_secs, int cap) {
    // age-out first, then the hard cap on what survives — a flood of fresh addrs
    // (one getaddr yields ~500) can't grow the table past `cap` even inside ttl.
    sqlite3_stmt *st;
    if (ttl_secs > 0 && sqlite3_prepare_v2(db,
            "DELETE FROM peers WHERE MAX(last_seen,last_good) < ?",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, now - ttl_secs);
        sqlite3_step(st); sqlite3_finalize(st);
    }
    if (cap > 0 && sqlite3_prepare_v2(db,
            "DELETE FROM peers WHERE addr NOT IN ("
            "  SELECT addr FROM peers ORDER BY MAX(last_seen,last_good) DESC LIMIT ?)",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, cap);
        sqlite3_step(st); sqlite3_finalize(st);
    }
}

void idx_db_block_put(sqlite3 *db, int64_t height, const uint8_t hash[32], int64_t time, int64_t coinbase, int64_t bytes, uint32_t bits) {
    sqlite3_stmt *st; sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO blocks(height,hash,time,coinbase,bytes,bits) VALUES(?,?,?,?,?,?)", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, height); sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, time); sqlite3_bind_int64(st, 4, coinbase); sqlite3_bind_int64(st, 5, bytes);
    sqlite3_bind_int64(st, 6, (int64_t)bits);
    sqlite3_step(st); sqlite3_finalize(st);
}
// header context for validation: time + bits of the block at `height`.
// bits == 0 on rows written before the column existed (validation grace).
int idx_db_block_hdr(sqlite3 *db, int64_t height, int64_t *time, uint32_t *bits) {
    sqlite3_stmt *st; sqlite3_prepare_v2(db, "SELECT time, bits FROM blocks WHERE height=?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, height); int found = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        if (time) *time = sqlite3_column_int64(st, 0);
        if (bits) *bits = (uint32_t)sqlite3_column_int64(st, 1);
        found = 1;
    }
    sqlite3_finalize(st); return found;
}
// the ≤11 stored timestamps directly below `height`, newest first (MTP input)
int idx_db_block_times(sqlite3 *db, int64_t height, int64_t out[11]) {
    sqlite3_stmt *st; sqlite3_prepare_v2(db,
        "SELECT time FROM blocks WHERE height<? ORDER BY height DESC LIMIT 11", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, height); int n = 0;
    while (n < 11 && sqlite3_step(st) == SQLITE_ROW) out[n++] = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st); return n;
}
int idx_db_block_get(sqlite3 *db, int64_t height, uint8_t hash[32]) {
    sqlite3_stmt *st; sqlite3_prepare_v2(db, "SELECT hash FROM blocks WHERE height=?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, height); int found = 0;
    if (sqlite3_step(st) == SQLITE_ROW) { const void *b = sqlite3_column_blob(st, 0); if (b && sqlite3_column_bytes(st, 0) == 32) { memcpy(hash, b, 32); found = 1; } }
    sqlite3_finalize(st); return found;
}
void idx_db_block_prune_above(sqlite3 *db, int64_t height) {
    sqlite3_stmt *st; sqlite3_prepare_v2(db, "DELETE FROM blocks WHERE height>?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, height); sqlite3_step(st); sqlite3_finalize(st);
    sqlite3_prepare_v2(db, "DELETE FROM raw_blocks WHERE height>?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, height); sqlite3_step(st); sqlite3_finalize(st);
    // epoch rows above the fork never happened on the surviving branch; rows at or
    // below it stand (replay re-derives the same rows, height-bounded → idempotent).
    sqlite3_prepare_v2(db, "DELETE FROM epochs WHERE start_height>?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, height); sqlite3_step(st); sqlite3_finalize(st);
    // wallet utxos ride the same cut: rows born above the fork vanish, spends
    // recorded above it un-mark (their tx may not exist on the new branch).
    sqlite3_prepare_v2(db, "DELETE FROM utxos WHERE height>?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, height); sqlite3_step(st); sqlite3_finalize(st);
    sqlite3_prepare_v2(db, "UPDATE utxos SET spent_height=NULL WHERE spent_height>?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, height); sqlite3_step(st); sqlite3_finalize(st);
}
int64_t idx_db_block_height_by_hash(sqlite3 *db, const uint8_t hash[32]) {
    sqlite3_stmt *st; sqlite3_prepare_v2(db, "SELECT height FROM blocks WHERE hash=?", -1, &st, NULL);
    sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
    int64_t h = -1; if (sqlite3_step(st) == SQLITE_ROW) h = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st); return h;
}

// ── raw carrier blocks (the reorg-replay substrate) ───────────────────────────
void idx_db_rawblock_put(sqlite3 *db, int64_t height, const uint8_t *raw, size_t len) {
    sqlite3_stmt *st; sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO raw_blocks(height,raw) VALUES(?,?)", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, height); sqlite3_bind_blob(st, 2, raw, (int)len, SQLITE_STATIC);
    sqlite3_step(st); sqlite3_finalize(st);
}
int idx_db_rawblock_iter(sqlite3 *db, int64_t max_height,
                         int (*cb)(void *u, int64_t height, const uint8_t *raw, size_t len), void *u) {
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT height, raw FROM raw_blocks WHERE height<=? ORDER BY height ASC", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, max_height);
    int n = 0, ok = 1;
    while (ok && sqlite3_step(st) == SQLITE_ROW) {
        ok = cb(u, sqlite3_column_int64(st, 0),
                (const uint8_t *)sqlite3_column_blob(st, 1), (size_t)sqlite3_column_bytes(st, 1));
        n++;
    }
    sqlite3_finalize(st); return ok ? n : -1;
}

// ── wallet watch list + UTXO tracking (display/wallet data, not engine state) ─
void idx_db_watch_add(sqlite3 *db, const uint8_t h160[20]) {
    sqlite3_stmt *st; sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO watch(h160) VALUES(?)", -1, &st, NULL);
    sqlite3_bind_blob(st, 1, h160, 20, SQLITE_STATIC); sqlite3_step(st); sqlite3_finalize(st);
}
int idx_db_watch_list(sqlite3 *db, uint8_t (*out)[20], int max) {
    sqlite3_stmt *st; sqlite3_prepare_v2(db, "SELECT h160 FROM watch", -1, &st, NULL);
    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW)
        if (sqlite3_column_bytes(st, 0) == 20) { memcpy(out[n], sqlite3_column_blob(st, 0), 20); n++; }
    sqlite3_finalize(st); return n;
}
void idx_db_utxo_put(sqlite3 *db, const uint8_t txid[32], uint32_t vout,
                     const uint8_t h160[20], int64_t value, int64_t height) {
    // IGNORE, not REPLACE: a conflicting row is always the same funding event
    // seen again (rollback replay, crash-recovery refold) — a funding that was
    // disconnected by a reorg is DELETEd by prune before any re-insert. REPLACE
    // would re-write spent_height=NULL and resurrect an already-spent output.
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO utxos(txid,vout,h160,value,height,spent_height) VALUES(?,?,?,?,?,NULL)", -1, &st, NULL);
    sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC); sqlite3_bind_int(st, 2, (int)vout);
    sqlite3_bind_blob(st, 3, h160, 20, SQLITE_STATIC);
    sqlite3_bind_int64(st, 4, value); sqlite3_bind_int64(st, 5, height);
    sqlite3_step(st); sqlite3_finalize(st);
}
int idx_db_utxo_spend(sqlite3 *db, const uint8_t txid[32], uint32_t vout, int64_t height) {
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "UPDATE utxos SET spent_height=? WHERE txid=? AND vout=?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, height);
    sqlite3_bind_blob(st, 2, txid, 32, SQLITE_STATIC); sqlite3_bind_int(st, 3, (int)vout);
    sqlite3_step(st); sqlite3_finalize(st);
    return sqlite3_changes(db);          // 1 if this input hit a watched utxo
}
// Oldest funding height still marked unspent (any watched address) — the floor
// a wallet re-walk must re-fold from. -1 when the table holds no unspent rows.
int64_t idx_db_utxo_min_unspent(sqlite3 *db) {
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT MIN(height) FROM utxos WHERE spent_height IS NULL", -1, &st, NULL);
    int64_t h = -1;
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL)
        h = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st); return h;
}
int idx_db_utxos(sqlite3 *db, const uint8_t h160[20],
                 void (*cb)(void *u, const uint8_t txid[32], uint32_t vout, int64_t value, int64_t height),
                 void *u) {
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT txid,vout,value,height FROM utxos"
                           " WHERE h160=? AND spent_height IS NULL ORDER BY value DESC", -1, &st, NULL);
    sqlite3_bind_blob(st, 1, h160, 20, SQLITE_STATIC);
    int n = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (sqlite3_column_bytes(st, 0) != 32) continue;
        if (cb) cb(u, (const uint8_t *)sqlite3_column_blob(st, 0), (uint32_t)sqlite3_column_int(st, 1),
                   sqlite3_column_int64(st, 2), sqlite3_column_int64(st, 3));
        n++;
    }
    sqlite3_finalize(st); return n;
}

// ── epochs projection (ownership history; see db.h) ───────────────────────────
void idx_db_epochs_mark(sqlite3 *db, int64_t height) {
    char b[32];
    if (meta_get(db, "epochs_from", b, sizeof b)) return;
    snprintf(b, sizeof b, "%lld", (long long)height);
    meta_set(db, "epochs_from", b);
}
void idx_db_epochs_wipe(sqlite3 *db) {
    sqlite3_exec(db, "DELETE FROM epochs; DELETE FROM meta WHERE k='epochs_from';", NULL, NULL, NULL);
}

void idx_db_epochs_update(sqlite3 *db, SmState *s, int64_t height) {
    sqlite3_stmt *q, *ins;
    // both queries are BOUNDED at `height`: during a reorg replay (or refold) the
    // table may still hold rows above the block being re-folded — the diff must
    // see exactly what the original fold saw, so re-derivation is a no-op.
    sqlite3_prepare_v2(db,
        "SELECT owner FROM epochs WHERE name=? AND start_height<=? ORDER BY start_height DESC LIMIT 1",
        -1, &q, NULL);
    sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO epochs(name,start_height,owner,owner_type) VALUES(?,?,?,?)",
        -1, &ins, NULL);
    for (int i = 0; i < s->n_names; i++) {
        SmNameRow *r = &s->names[i];
        sqlite3_reset(q);
        sqlite3_bind_text (q, 1, r->name, r->name_len, SQLITE_STATIC);
        sqlite3_bind_int64(q, 2, height);
        int changed = 1;
        if (sqlite3_step(q) == SQLITE_ROW &&
            sqlite3_column_type(q, 0) != SQLITE_NULL && sqlite3_column_bytes(q, 0) == 20 &&
            memcmp(sqlite3_column_blob(q, 0), r->owner, 20) == 0)
            changed = 0;
        if (changed) {
            sqlite3_reset(ins);
            sqlite3_bind_text (ins, 1, r->name, r->name_len, SQLITE_STATIC);
            sqlite3_bind_int64(ins, 2, height);
            sqlite3_bind_blob (ins, 3, r->owner, 20, SQLITE_STATIC);
            sqlite3_bind_int  (ins, 4, r->owner_type);
            sqlite3_step(ins);
        }
    }
    sqlite3_finalize(q);
    // lapses: names whose latest recorded epoch (≤ height) is open but that have
    // left the live state get a NULL (unowned-from-here) row.
    sqlite3_stmt *open;
    sqlite3_prepare_v2(db,
        "SELECT e.name FROM epochs e WHERE e.owner IS NOT NULL AND e.start_height<=?1"
        " AND e.start_height=(SELECT MAX(start_height) FROM epochs WHERE name=e.name AND start_height<=?1)",
        -1, &open, NULL);
    sqlite3_bind_int64(open, 1, height);
    while (sqlite3_step(open) == SQLITE_ROW) {
        const char *nm = (const char *)sqlite3_column_text(open, 0);
        if (sm_lookup(s, nm)) continue;                        // still owned
        sqlite3_reset(ins);
        sqlite3_bind_text (ins, 1, nm, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(ins, 2, height);
        sqlite3_bind_null (ins, 3);
        sqlite3_bind_int  (ins, 4, 0);
        sqlite3_step(ins);
    }
    sqlite3_finalize(open);
    sqlite3_finalize(ins);
    idx_db_epochs_mark(db, height);
}

int idx_db_owner_at(sqlite3 *db, const char *name, int name_len, int64_t height,
                    uint8_t owner[20], uint8_t *owner_type) {
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT owner,owner_type FROM epochs WHERE name=? AND start_height<=?"
        " ORDER BY start_height DESC LIMIT 1", -1, &st, NULL);
    sqlite3_bind_text (st, 1, name, name_len, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, height);
    int rc = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) != SQLITE_NULL && sqlite3_column_bytes(st, 0) == 20) {
            if (owner) memcpy(owner, sqlite3_column_blob(st, 0), 20);
            if (owner_type) *owner_type = (uint8_t)sqlite3_column_int(st, 1);
            rc = 1;
        } else rc = 0;                                         // lapse row: known-unowned
    } else {
        // No row ≤ height. If history covers this height (epochs_from ≤ height),
        // absence is definitive — EXCEPT for a name whose first row sits exactly AT
        // epochs_from: on a mid-history deployment that row is the bulk backfill of
        // names that already existed, so heights before it are genuinely unknown.
        // (A complete-history DB — fresh sync from the checkpoint, or a refold —
        // marks epochs_from before any claim can exist, so its first rows never
        // coincide with the marker and absence stays definitive.)
        char b[32];
        if (meta_get(db, "epochs_from", b, sizeof b) && strtoll(b, NULL, 10) <= height) {
            int64_t efrom = strtoll(b, NULL, 10);
            sqlite3_stmt *first;
            sqlite3_prepare_v2(db, "SELECT MIN(start_height) FROM epochs WHERE name=?", -1, &first, NULL);
            sqlite3_bind_text(first, 1, name, name_len, SQLITE_STATIC);
            if (sqlite3_step(first) == SQLITE_ROW && sqlite3_column_type(first, 0) != SQLITE_NULL) {
                rc = (sqlite3_column_int64(first, 0) == efrom) ? -1 : 0;
            } else {
                // no rows at all: alive-now means it predates the projection (unknown);
                // never-seen means it never existed in covered history (unowned)
                sqlite3_stmt *cur;
                sqlite3_prepare_v2(db, "SELECT 1 FROM names WHERE name=? LIMIT 1", -1, &cur, NULL);
                sqlite3_bind_text(cur, 1, name, name_len, SQLITE_STATIC);
                rc = (sqlite3_step(cur) == SQLITE_ROW) ? -1 : 0;
                sqlite3_finalize(cur);
            }
            sqlite3_finalize(first);
        }
    }
    sqlite3_finalize(st);
    return rc;
}

int idx_db_oracle_warm(sqlite3 *db, void *oracle) {
    sqlite3_stmt *st; sqlite3_prepare_v2(db, "SELECT height,time,coinbase,bytes FROM blocks ORDER BY height ASC", -1, &st, NULL);
    int n = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        oracle_record((OracleFeed *)oracle, sqlite3_column_int64(st, 0), sqlite3_column_int64(st, 1), sqlite3_column_int64(st, 2), sqlite3_column_int64(st, 3));
        n++;
    }
    sqlite3_finalize(st); return n;
}

// ── projection ───────────────────────────────────────────────────────────────
// Rebuilds the projection tables + the proj_height sentinel in ONE transaction.
// EVERY step is error-checked: if any INSERT fails (disk full, I/O error) the whole
// transaction is ROLLED BACK and proj_height is NOT advanced — so a crash/failure
// never leaves a half-rebuilt `names` table stamped as complete. On failure the
// in-RAM SmState remains authoritative and the next projection retries; a restart
// sees the old proj_height and re-folds the gap. Returns 1 on commit, 0 on rollback.
int idx_db_project(sqlite3 *db, SmState *s) {
    if (sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) return 0;
    int ok = sqlite3_exec(db, "DELETE FROM names; DELETE FROM commits; DELETE FROM muts;", NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_stmt *st = NULL;
    if (ok) ok = sqlite3_prepare_v2(db, "INSERT INTO names(name,owner,owner_type,lease_expiry,st,seller,seller_type,price,offer_expiry,buyer,burn_leg,pay_leg,reserve_expiry) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", -1, &st, NULL) == SQLITE_OK;
    for (int i = 0; ok && i < s->n_names; i++) {
        SmNameRow *r = &s->names[i];
        sqlite3_reset(st);
        sqlite3_bind_text (st, 1, r->name, r->name_len, SQLITE_STATIC);
        sqlite3_bind_blob (st, 2, r->owner, 20, SQLITE_STATIC); sqlite3_bind_int(st, 3, r->owner_type);
        sqlite3_bind_int64(st, 4, r->lease_expiry); sqlite3_bind_int(st, 5, (int)r->st);
        sqlite3_bind_blob (st, 6, r->seller, 20, SQLITE_STATIC); sqlite3_bind_int(st, 7, r->seller_type);
        sqlite3_bind_int64(st, 8, (int64_t)r->price); sqlite3_bind_int64(st, 9, r->offer_expiry);
        sqlite3_bind_blob (st,10, r->buyer, 20, SQLITE_STATIC);
        sqlite3_bind_int64(st,11, (int64_t)r->burn_leg); sqlite3_bind_int64(st,12, (int64_t)r->pay_leg);
        sqlite3_bind_int64(st,13, r->reserve_expiry);
        if (sqlite3_step(st) != SQLITE_DONE) ok = 0;
    }
    sqlite3_finalize(st); st = NULL;
    if (ok) ok = sqlite3_prepare_v2(db, "INSERT INTO commits(commitment,commit_height,tx_index,commit_time) VALUES(?,?,?,?)", -1, &st, NULL) == SQLITE_OK;
    for (int i = 0; ok && i < s->n_commits; i++) {
        SmCommit *c = &s->commits[i]; sqlite3_reset(st);
        sqlite3_bind_blob(st, 1, c->commitment, 32, SQLITE_STATIC); sqlite3_bind_int64(st, 2, c->commit_height);
        sqlite3_bind_int64(st, 3, c->tx_index); sqlite3_bind_int64(st, 4, c->commit_time);
        if (sqlite3_step(st) != SQLITE_DONE) ok = 0;
    }
    sqlite3_finalize(st); st = NULL;
    if (ok) ok = sqlite3_prepare_v2(db, "INSERT INTO muts(owner,height) VALUES(?,?)", -1, &st, NULL) == SQLITE_OK;
    for (int i = 0; ok && i < s->n_muts; i++) {
        SmMut *m = &s->muts[i]; sqlite3_reset(st); sqlite3_bind_blob(st, 1, m->owner, 20, SQLITE_STATIC); sqlite3_bind_int64(st, 2, m->height);
        if (sqlite3_step(st) != SQLITE_DONE) ok = 0;
    }
    sqlite3_finalize(st);
    // Sentinel: the height this projection reflects, written INSIDE the same
    // transaction so it commits atomically with the rebuilt tables (or not at all).
    if (ok) { char hb[32]; snprintf(hb, sizeof hb, "%lld", (long long)s->cur_height); ok = meta_set(db, "proj_height", hb); }
    if (ok && sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK) return 1;
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);   // leave the prior projection + proj_height intact
    return 0;
}
int64_t idx_db_projected_height(sqlite3 *db) {
    char b[32]; return meta_get(db, "proj_height", b, sizeof b) ? strtoll(b, NULL, 10) : -1;
}

int idx_db_load_state(sqlite3 *db, SmState *s) {
    int n = 0; sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT name,owner,owner_type,lease_expiry,st,seller,seller_type,price,offer_expiry,buyer,burn_leg,pay_leg,reserve_expiry FROM names", -1, &st, NULL);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 0); int nl = sqlite3_column_bytes(st, 0);
        SmNameRow *r = sm_add_name(s, name, (size_t)nl);
        memcpy(r->owner, sqlite3_column_blob(st, 1), 20); r->owner_type = (uint8_t)sqlite3_column_int(st, 2);
        r->lease_expiry = sqlite3_column_int64(st, 3); r->st = (SmNameState)sqlite3_column_int(st, 4);
        memcpy(r->seller, sqlite3_column_blob(st, 5), 20); r->seller_type = (uint8_t)sqlite3_column_int(st, 6);
        r->price = (uint64_t)sqlite3_column_int64(st, 7); r->offer_expiry = sqlite3_column_int64(st, 8);
        memcpy(r->buyer, sqlite3_column_blob(st, 9), 20);
        r->burn_leg = (uint64_t)sqlite3_column_int64(st, 10); r->pay_leg = (uint64_t)sqlite3_column_int64(st, 11);
        r->reserve_expiry = sqlite3_column_int64(st, 12); n++;
    }
    sqlite3_finalize(st);
    sqlite3_prepare_v2(db, "SELECT commitment,commit_height,tx_index,commit_time FROM commits", -1, &st, NULL);
    while (sqlite3_step(st) == SQLITE_ROW) {
        sm_commit_add(s, sqlite3_column_blob(st, 0), sqlite3_column_int64(st, 1), (uint32_t)sqlite3_column_int64(st, 2), sqlite3_column_int64(st, 3)); n++;
    }
    sqlite3_finalize(st);
    sqlite3_prepare_v2(db, "SELECT owner,height FROM muts", -1, &st, NULL);
    while (sqlite3_step(st) == SQLITE_ROW) { sm_bump_mutation(s, sqlite3_column_blob(st, 0), sqlite3_column_int64(st, 1)); n++; }
    sqlite3_finalize(st);
    return n;
}

int idx_db_resolve(sqlite3 *db, const char *name, char owner_hex[41], char *state_out) {
    sqlite3_stmt *st; sqlite3_prepare_v2(db, "SELECT owner,st FROM names WHERE name=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC); int found = 0;
    if (sqlite3_step(st) == SQLITE_ROW) { tohex(sqlite3_column_blob(st, 0), 20, owner_hex); if (state_out) *state_out = (char)sqlite3_column_int(st, 1); found = 1; }
    sqlite3_finalize(st); return found;
}
int idx_db_name_row(sqlite3 *db, const char *name, IdxNameRow *out) {
    sqlite3_stmt *st; int found = 0;
    sqlite3_prepare_v2(db, "SELECT owner,owner_type,lease_expiry,st,seller,seller_type,price,offer_expiry,buyer,burn_leg,pay_leg,reserve_expiry FROM names WHERE name=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        memset(out, 0, sizeof *out);
        memcpy(out->owner, sqlite3_column_blob(st, 0), 20); out->owner_type = (uint8_t)sqlite3_column_int(st, 1);
        out->lease_expiry = sqlite3_column_int64(st, 2); out->st = sqlite3_column_int(st, 3);
        memcpy(out->seller, sqlite3_column_blob(st, 4), 20); out->seller_type = (uint8_t)sqlite3_column_int(st, 5);
        out->price = (uint64_t)sqlite3_column_int64(st, 6); out->offer_expiry = sqlite3_column_int64(st, 7);
        memcpy(out->buyer, sqlite3_column_blob(st, 8), 20);
        out->burn_leg = (uint64_t)sqlite3_column_int64(st, 9); out->pay_leg = (uint64_t)sqlite3_column_int64(st, 10);
        out->reserve_expiry = sqlite3_column_int64(st, 11); found = 1;
    }
    sqlite3_finalize(st); return found;
}
int idx_db_owned(sqlite3 *db, const char *h160hex, void (*cb)(void *, const char *, int64_t, int), void *u) {
    uint8_t owner[20]; if (strlen(h160hex) != 40) return 0;
    for (int i = 0; i < 20; i++) { unsigned v; if (sscanf(h160hex + 2*i, "%2x", &v) != 1) return 0; owner[i] = (uint8_t)v; }
    sqlite3_stmt *st; sqlite3_prepare_v2(db, "SELECT name,lease_expiry,st FROM names WHERE owner=? ORDER BY name", -1, &st, NULL);
    sqlite3_bind_blob(st, 1, owner, 20, SQLITE_STATIC); int n = 0;
    while (sqlite3_step(st) == SQLITE_ROW) { if (cb) cb(u, (const char *)sqlite3_column_text(st, 0), sqlite3_column_int64(st, 1), sqlite3_column_int(st, 2)); n++; }
    sqlite3_finalize(st); return n;
}

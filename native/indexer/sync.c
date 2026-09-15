// sync.c — CLI driver: offline `index`, the `resolve`/`owned`/`digest` queries,
// and the live P2P `sync` loop. The fold + projection are the proven path
// (selftest); P2P here connects a Dogecoin-family node (doge/pep), pulls blocks
// via getblocks/inv/getdata, and drives the same adapter→engine→projection
// pipeline per block.
#include "indexer.h"
#include "chain.h"
#include "adapter.h"
#include "base58.h"
#include "db.h"
#include "oracle_feed.h"
#include "pow.h"
#include "serve_store.h"
#include "mempool.h"
#include "txcheck.h"
#include "sm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/random.h>
#include <time.h>

// subver classifier: does this agent carry the overlay discovery mark?
// (IDX_DNET_MARK, indexer.h — build-time per deployment, "/pepenet-" default)
#define AGENT_MARKED(a) (!strncmp((a), IDX_DNET_MARK, sizeof IDX_DNET_MARK - 1))

// ── coin params (host-chain profile — see docs/notes/host-profiles.md) ────────
// `start` = the pinned sync-bootstrap checkpoint: a fresh DB stands on this
// (height, hash) and the first getblocks locator anchors there, so the peer serves
// start+1 onward and our height counter matches real chain heights. The checkpoint
// is profile-pinned because rates are only network-deterministic when every indexer
// has the same oracle window — ACTIVATION_HEIGHT must be ≥ start + FEE_WINDOW + 1.
// Hash is in internal (little-endian) byte order.
typedef struct {
    const char *name; uint8_t magic[4]; uint16_t port; int64_t activation;
    int64_t start; uint8_t start_hash[32];
    int64_t subsidy;         // §3.4 flat-tail subsidy (koinu/block); consensus-critical per host
    const char *seeds[3];    // the host chain's own DNS seeds (Core's vSeeds hosts),
                             // NULL-terminated — the last-resort sync candidates
    // PoW validation profile (pow.h): powlimit == 0 skips validation entirely
    // (test profiles sync synthetic fixture chains). start_bits/start_time/
    // start_prev_time pin the checkpoint header — the Digishield + MTP anchor
    // for the first blocks a fresh db accepts (fetched from the live chains,
    // scripts/fetchblk-style, when the checkpoint was pinned).
    uint32_t powlimit, aux_chain_id, start_bits;
    int64_t  start_time, start_prev_time;
} Coin;
#define SUBSIDY_10K  (10000LL * SM_KOINU_PER_DOGE)
static const Coin COINS[] = {
    { "doge",    { 0xC0, 0xC0, 0xC0, 0xC0 }, 22556, 0, 6264000,  // checkpoint re-pinned near tip
      // (block 6,264,000 = edd25ca2…fdb6, 2026-06-25) for a live-rate reading; activation
      // passed on the CLI (= start + FEE_WINDOW + 1). Internal (little-endian) byte order.
      { 0xb6, 0xfd, 0xb0, 0xe4, 0xb9, 0x79, 0xe2, 0x88, 0x01, 0x7a, 0x39, 0x8a, 0x2c, 0x5f, 0xca, 0xc8,
        0x53, 0x53, 0x3e, 0x93, 0xd5, 0xa3, 0xc9, 0xe4, 0x7a, 0x05, 0x37, 0x07, 0xa2, 0x5c, 0xd2, 0xed }, SUBSIDY_10K,
      { "seed.multidoge.org", "seed2.multidoge.org", NULL },
      0x1e0fffff, 0x62, 0x1a00969d, 1782425940, 1782425922 },
    // Pepecoin mainnet (Dogecoin 1.14 fork; same 1-min blocks + flat 10k tail subsidy).
    // Names activate at block 1,130,000 (re-pinned 2026-07-20 for the 0xFF 'P' 'N'
    // prefix relaunch); the fold checkpoint (start) is pinned at 1,119,000 (header
    // cda615cf…fad1bb, 2026-07-11 — genesis-walked and chain-linked up to the
    // prior 1,122,000 pin before adoption). start sits 11,000 blocks below
    // activation, so the §3.4 oracle window (FEE_WINDOW 10,081, fed from
    // start+1) is FULL from block 1,129,082 — every rate the fold ever computes
    // is a full-window rate; no partial-window launch case. Re-pinning start
    // ORPHANS dbs synced from the old 1,122,000 pin (their rates at
    // 1,130,000..1,132,081 were partial-window): delete the db and resync.
    // Internal (little-endian) byte order.
    { "pep",     { 0xC0, 0xA0, 0xF0, 0xE0 }, 33874, 1130000, 1119000,
      { 0xbb,0xd1,0xfa,0xd7,0x7f,0xd3,0xf2,0x40,0x05,0xfc,0x5f,0x62,0xc4,0x1d,0xb7,0x8b,
        0xc2,0xf2,0x19,0x0e,0x44,0x2c,0x45,0xbd,0xb7,0x57,0xe5,0x68,0xcf,0x15,0xa6,0xcd }, SUBSIDY_10K,
      { "seeds.pepecoin.org", "seeds.pepeblocks.com", NULL },
      0x1e0fffff, 0x3f, 0x196ac0dc, 1783774438, 1783774393 },
    { "testnet", { 0xFC, 0xC1, 0xB7, 0xDC }, 44556, 0, 0,
      { 0x9e,0x55,0x50,0x73,0xd0,0xc4,0xf3,0x64,0x56,0xdb,0x89,0x51,0xf4,0x49,0x70,0x4d,
        0x54,0x4d,0x28,0x26,0xd9,0xaa,0x60,0x63,0x6b,0x40,0x37,0x46,0x26,0x78,0x0a,0xbb }, SUBSIDY_10K,
      { NULL }, 0, 0, 0, 0, 0 },       // powlimit 0 = validation off (fixtures)
    { "regtest", { 0xFA, 0xBF, 0xB5, 0xDA }, 18444, 0, 0,
      { 0xa5,0x73,0xe9,0x1c,0x17,0x72,0x07,0x6c,0x0d,0x40,0xf7,0x0e,0x44,0x08,0xc8,0x3a,
        0x31,0x70,0x5f,0x29,0x6a,0xe6,0xe7,0x62,0x9d,0x4a,0xdc,0xb5,0xa3,0x60,0x21,0x3d }, SUBSIDY_10K,
      { NULL }, 0, 0, 0, 0, 0 },       // powlimit 0 = validation off (fixtures)
};
static const Coin *coin_by_name(const char *n) {
    for (unsigned i = 0; i < sizeof COINS / sizeof COINS[0]; i++) if (!strcmp(COINS[i].name, n)) return &COINS[i];
    return NULL;
}

uint16_t idx_coin_port(const char *coin) {
    const Coin *c = coin_by_name(coin);
    return c ? c->port : 0;
}

// ── fold-block context (shared by offline + P2P) ─────────────────────────────
#define IDX_MAX_WATCH 16
typedef struct { SmState *s; sqlite3 *db; OracleFeed *oracle; int folded;
                 int64_t height;
                 int wallet_touched;   // this block put or spent a watched utxo
                 ServeStore *serve;    // NULL unless this pass feeds the serve cache
                 uint8_t watch[IDX_MAX_WATCH][20]; int nwatch; } FoldCtx;
static void fold_load_watch(FoldCtx *fc) {
    fc->nwatch = fc->db ? idx_db_watch_list(fc->db, fc->watch, IDX_MAX_WATCH) : 0;
}
static void tx_cb(void *u, const IdxTx *tx, uint32_t txindex) {
    FoldCtx *fc = (FoldCtx *)u;
    int r = idx_adapt_tx(fc->s, tx, txindex);
    if (r == 1) fc->folded++;
    // wallet watch: record outputs paying a watched P2PKH, mark spends of known
    // utxos. Only from the block AFTER the watch is registered — register (and
    // the wallet address) before funding it.
    if (fc->nwatch && fc->db) {
        for (int o = 0; o < tx->n_out; o++) {
            uint8_t h160[20], type;
            if (!idx_script_payee(tx->outs[o].spk, tx->outs[o].spklen, h160, &type) || type != 0) continue;
            for (int w = 0; w < fc->nwatch; w++)
                if (!memcmp(h160, fc->watch[w], 20)) {
                    idx_db_utxo_put(fc->db, tx->txid, tx->outs[o].vout, h160,
                                    tx->outs[o].value, fc->height);
                    fc->wallet_touched = 1;
                    break;
                }
        }
        for (int i = 0; i < tx->n_in; i++) {      // prevout = txid(32) + vout(4 LE)
            const uint8_t *po = tx->ins[i].prevout;
            uint32_t vout = (uint32_t)po[32] | (uint32_t)po[33] << 8 |
                            (uint32_t)po[34] << 16 | (uint32_t)po[35] << 24;
            if (vout == 0xFFFFFFFF) continue;     // coinbase
            if (idx_db_utxo_spend(fc->db, po, vout, fc->height) > 0)
                fc->wallet_touched = 1;
        }
    }
    // relay mempool: this tx just confirmed — drop it (and anything that now
    // double-spends it) from the pool. No-op while the pool is empty (fast path).
    mempool_on_confirmed_tx(tx->txid, tx);
}

// Connect one block at `height`: oracle → begin_block → parse+fold → record/persist.
static int connect_block(FoldCtx *fc, int64_t height, const uint8_t *raw, size_t len) {
    IdxBlockMeta meta;
    int64_t mtp; uint64_t rate;
    fc->height = height;
    oracle_for_height(fc->oracle, height, &mtp, &rate);
    int64_t lapses_before = fc->s->ev[SM_EV_LAPSE];
    sm_begin_block(fc->s, height, mtp, rate);
    int folded_before = fc->folded;
    fc->wallet_touched = 0;
    if (!idx_parse_block(raw, len, &meta, tx_cb, fc)) { fprintf(stderr, "block %lld malformed\n", (long long)height); return 0; }
    oracle_record(fc->oracle, height, meta.time, meta.coinbase_out_total, meta.block_bytes);
    if (fc->db) {
        idx_db_block_put(fc->db, height, meta.block_hash, meta.time, meta.coinbase_out_total, meta.block_bytes, meta.bits);
        // reorg-replay substrate: keep the raw bytes of carrier blocks AND
        // wallet-touching blocks — replay must re-see wallet spends too, or a
        // rollback would leave spent outputs looking unspent (they were, once:
        // the pre-repair builds' resurrected-balance bug).
        if (fc->folded > folded_before || fc->wallet_touched)
            idx_db_rawblock_put(fc->db, height, raw, len);
        // serve cache (NODE_NETWORK_LIMITED): every header + a rolling 288-block
        // window, in its own aux db. len >= 80 guaranteed (parse succeeded).
        if (fc->serve) serve_store_put(fc->serve, height, meta.block_hash, raw, raw, len, height);
        // epochs projection: ownership can only change in a block that folded a
        // carrier tx or fired a lapse — diff those blocks against recorded history
        if (fc->folded > folded_before || fc->s->ev[SM_EV_LAPSE] != lapses_before)
            idx_db_epochs_update(fc->db, fc->s, height);
        idx_db_save_sync(fc->db, height, meta.block_hash);
    }
    return 1;
}

// ── reorg rollback ────────────────────────────────────────────────────────────
static int rollback_replay_cb(void *u, int64_t height, const uint8_t *raw, size_t len) {
    FoldCtx *fc = (FoldCtx *)u;
    IdxBlockMeta meta; int64_t mtp; uint64_t rate;
    fc->height = height;
    oracle_for_height(fc->oracle, height, &mtp, &rate);
    int64_t lapses_before = fc->s->ev[SM_EV_LAPSE];
    sm_begin_block(fc->s, height, mtp, rate);
    int folded_before = fc->folded;
    if (!idx_parse_block(raw, len, &meta, tx_cb, fc)) return 0;
    // re-derive epoch rows (height-bounded ⇒ idempotent over what already stands).
    // Replay walks carrier blocks only, so a lapse between them lands at the NEXT
    // carrier block's height — after a refold wipe, lapse edges carry that
    // granularity (the live fold, which sees every block, records them exactly).
    if (fc->db && (fc->folded > folded_before || fc->s->ev[SM_EV_LAPSE] != lapses_before))
        idx_db_epochs_update(fc->db, fc->s, height);
    return 1;
}
// Roll the fold back to `to_height` (kept): prune every height-keyed projection
// above it, drop its oracle rows, and rebuild the state by replaying the stored
// raw blocks ≤ to_height in order (carrier blocks + wallet-touching blocks) — a
// byte-identical refold, because the skipped blocks touch no state and their
// oracle rows (all heights) are already in the feed. The wallet blocks in the
// substrate re-mark spends the replayed carrier funds would otherwise shed.
// Replaces *s (old state freed). Returns 1, 0 on failure.
int idx_sync_rollback(SmState **s, sqlite3 *db, OracleFeed *oracle,
                      int64_t activation, int64_t to_height) {
    idx_db_block_prune_above(db, to_height);
    oracle_rollback(oracle, to_height + 1);
    sm_free(*s);
    *s = sm_new((uint64_t)activation);
    FoldCtx fc = { .s = *s, .db = db, .oracle = oracle };
    fold_load_watch(&fc);
    if (idx_db_rawblock_iter(db, to_height, rollback_replay_cb, &fc) < 0) return 0;
    // The replayed state stands at to_height (carrier-less blocks past the last
    // carrier touch nothing) — stamp the cursor so the projection records that,
    // not the last carrier's height (or 0 for a carrier-less range).
    (*s)->cur_height = to_height;
    idx_db_project(db, *s);
    return 1;
}

// ── file helpers ──────────────────────────────────────────────────────────────
// Sanity bound on anything we slurp whole (block files, raw or hex-text). Far
// above any real Doge block even hex-doubled; keeps a bogus/huge path from
// turning into a blind malloc.
#define IDX_READ_FILE_MAX  (256u * 1024 * 1024)
static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    // ftell returns -1 on an unseekable stream or a directory; unchecked, the
    // (size_t)n + 1 below wraps to malloc(0) and fread is then asked for
    // SIZE_MAX bytes into it. Check every seek/tell and bail cleanly.
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0 || (unsigned long)n > IDX_READ_FILE_MAX) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)n + 1); if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
    fclose(f); buf[n] = 0; *len = (size_t)n; return buf;
}
// Accept a hex-text or raw-binary block file. Returns malloc'd bytes.
static uint8_t *load_block(const char *path, size_t *len) {
    size_t n; uint8_t *raw = read_file(path, &n); if (!raw) return NULL;
    int ishex = (n >= 160) && (n % 2 == 0);
    for (size_t i = 0; i < n && ishex; i++) { char c = (char)raw[i]; if (!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')||c=='\n'||c=='\r'||c==' ')) ishex = 0; }
    if (!ishex) { *len = n; return raw; }
    // strip whitespace + hex-decode
    char *h = (char *)raw; size_t hn = 0; for (size_t i = 0; i < n; i++) { char c = h[i]; if (c=='\n'||c=='\r'||c==' '||c=='\t') continue; h[hn++] = c; }
    uint8_t *out = malloc(hn / 2 + 1); size_t ol;
    if (!idx_hex_to_bytes(h, out, hn / 2, &ol)) { free(raw); free(out); return NULL; }
    free(raw); *len = ol; return out;
}

// ── commands ──────────────────────────────────────────────────────────────────
static void print_digest(SmState *s) {
    uint8_t d[32], e[32]; char hd[65], he[65];
    sm_state_digest(s, d); sm_state_ecmh(s, e);
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { hd[2*i] = H[d[i]>>4]; hd[2*i+1] = H[d[i]&15]; he[2*i] = H[e[i]>>4]; he[2*i+1] = H[e[i]&15]; }
    hd[64] = he[64] = 0;
    printf("state_digest %s\nstate_ecmh   %s\n", hd, he);
}

static int cmd_index(int argc, char **argv) {
    // index <db> <activation> <blockfile> [blockfile...]   (heights start at 0)
    if (argc < 5) { fprintf(stderr, "usage: index <db> <activation_height> <blockfile> [more...]\n"); return 2; }
    const char *dbpath = argv[2]; int64_t activation = strtoll(argv[3], NULL, 10);
    sqlite3 *db = idx_db_open(dbpath); if (!db) { fprintf(stderr, "cannot open %s\n", dbpath); return 1; }
    idx_db_set_activation(db, activation);
    SmState *s = sm_new((uint64_t)activation);
    OracleFeed *oracle = oracle_new();
    idx_db_load_state(db, s); idx_db_oracle_warm(db, oracle); oracle_set_subsidy(oracle, idx_db_get_subsidy(db, SUBSIDY_10K));
    int64_t height = 0; uint8_t tip[32];
    if (idx_db_load_sync(db, &height, tip)) height++;   // resume after stored tip
    else idx_db_epochs_mark(db, 0);                     // fresh DB: coverage from genesis
    FoldCtx fc = { .s = s, .db = db, .oracle = oracle };
    fold_load_watch(&fc);
    for (int i = 4; i < argc; i++, height++) {
        size_t len; uint8_t *raw = load_block(argv[i], &len);
        if (!raw) { fprintf(stderr, "cannot read block %s\n", argv[i]); idx_db_close(db); return 1; }
        if (!connect_block(&fc, height, raw, len)) { free(raw); idx_db_close(db); return 1; }
        free(raw);
    }
    idx_db_project(db, s);
    printf("indexed to height %lld (%d action-txs folded)\n", (long long)(height - 1), fc.folded);
    print_digest(s);
    oracle_free(oracle); sm_free(s); idx_db_close(db);
    return 0;
}

static SmState *open_state(const char *dbpath, sqlite3 **db_out) {
    sqlite3 *db = idx_db_open(dbpath); if (!db) return NULL;
    SmState *s = sm_new((uint64_t)idx_db_get_activation(db, 0));
    idx_db_load_state(db, s);
    *db_out = db; return s;
}

static void hex20(const uint8_t *b, char out[41]) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 20; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[40] = 0;
}
static void print_ts(const char *label, int64_t t) {
    char when[32] = "";
    if (t > 0) { time_t tt = (time_t)t; struct tm tm; gmtime_r(&tt, &tm); strftime(when, sizeof when, "%Y-%m-%d %H:%M", &tm); }
    printf("  %-15s %lld  (%s)\n", label, (long long)t, when);
}
static int cmd_resolve(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: resolve <db> <name>\n"); return 2; }
    sqlite3 *db = idx_db_open(argv[2]); if (!db) { fprintf(stderr, "cannot open db\n"); return 1; }
    IdxNameRow r;
    if (idx_db_name_row(db, argv[3], &r)) {
        static const char *names[] = { "OWNED", "LISTED", "OFFERED", "RESERVED" };
        char h[41]; hex20(r.owner, h);
        printf("%s  state=%s\n  %-15s %s (type %u)\n", argv[3],
               (r.st >= 0 && r.st < 4) ? names[r.st] : "?", "owner", h, r.owner_type);
        print_ts("lease_expiry", r.lease_expiry);
        if (r.st != SM_OWNED) {                                  // §3.7 market fields
            hex20(r.seller, h);
            printf("  %-15s %s (type %u)\n", "seller", h, r.seller_type);
            printf("  %-15s %llu koinu\n", "price", (unsigned long long)r.price);
            print_ts("offer_expiry", r.offer_expiry);
            if (r.st == SM_OFFERED || r.st == SM_RESERVED) {
                hex20(r.buyer, h);
                printf("  %-15s %s\n", r.st == SM_OFFERED ? "buyer (SELL_TO)" : "reserver", h);
            }
            if (r.st == SM_RESERVED) {
                printf("  %-15s burn=%llu pay=%llu (credited at settle)\n", "deposit legs",
                       (unsigned long long)r.burn_leg, (unsigned long long)r.pay_leg);
                printf("  %-15s %llu koinu\n", "remainder", (unsigned long long)(r.price - r.burn_leg - r.pay_leg));
                print_ts("reserve_expiry", r.reserve_expiry);
            }
        }
    } else printf("%s  (unowned)\n", argv[3]);
    idx_db_close(db); return 0;
}

static void owned_cb(void *u, const char *name, int64_t lease, int st) { (void)u; (void)st; printf("  %-20s lease_expiry=%lld\n", name, (long long)lease); }
static int cmd_owned(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: owned <db> <hash160hex>\n"); return 2; }
    sqlite3 *db; SmState *s = open_state(argv[2], &db); if (!s) { fprintf(stderr, "cannot open db\n"); return 1; }
    int n = idx_db_owned(db, argv[3], owned_cb, NULL);
    if (!n) printf("  (no names)\n");
    sm_free(s); idx_db_close(db); return 0;
}

static int cmd_digest(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: digest <db>\n"); return 2; }
    sqlite3 *db; SmState *s = open_state(argv[2], &db); if (!s) { fprintf(stderr, "cannot open db\n"); return 1; }
    int64_t h = 0; uint8_t tip[32];
    if (idx_db_load_sync(db, &h, tip)) {
        printf("height %lld\n", (long long)h);
        OracleFeed *o = oracle_new();                     // live §3.4 rate for the NEXT block
        idx_db_oracle_warm(db, o);
        int64_t mtp; uint64_t rate;
        oracle_for_height(o, h + 1, &mtp, &rate);
        printf("rate   %llu koinu/name-quantum (%lld koinu buys 1 name-year)\n",
               (unsigned long long)rate, (long long)(13 * (int64_t)rate));
        oracle_free(o);
    }
    print_digest(s);
    sm_free(s); idx_db_close(db); return 0;
}

// refold <db> — rebuild the fold state from LOCAL data under the current engine
// rules: the oracle re-warmed from the blocks table, the state replayed from the
// stored raw carrier blocks. The consensus-change tool: after a rule re-pin the
// projection is rebuilt in seconds without touching the network.
static int cmd_refold(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: refold <db>\n"); return 2; }
    sqlite3 *db = idx_db_open(argv[2]); if (!db) { fprintf(stderr, "cannot open db\n"); return 1; }
    int64_t height = 0; uint8_t tip[32];
    if (!idx_db_load_sync(db, &height, tip)) { fprintf(stderr, "db has no sync state\n"); idx_db_close(db); return 1; }
    int64_t activation = idx_db_get_activation(db, 0);
    SmState *s = sm_new((uint64_t)activation);
    OracleFeed *oracle = oracle_new();
    idx_db_oracle_warm(db, oracle); oracle_set_subsidy(oracle, idx_db_get_subsidy(db, SUBSIDY_10K));
    // refold = the rules may have changed: recorded epochs could be wrong under the
    // new fold. Wipe and re-derive the whole history from the raw carrier blocks
    // (complete coverage — mark from genesis; lapse edges land at carrier-block
    // granularity, see rollback_replay_cb).
    idx_db_epochs_wipe(db);
    idx_db_epochs_mark(db, 0);
    if (!idx_sync_rollback(&s, db, oracle, activation, height)) {
        fprintf(stderr, "refold failed\n");
        oracle_free(oracle); sm_free(s); idx_db_close(db); return 1;
    }
    printf("refolded to height %lld (activation %lld)\n", (long long)height, (long long)activation);
    print_digest(s);
    oracle_free(oracle); sm_free(s); idx_db_close(db);
    return 0;
}

static int cmd_watch(int argc, char **argv) {
    // watch <db> <address|hash160hex> — register a wallet address for UTXO
    // tracking. Takes effect from the NEXT synced block: register before funding.
    if (argc < 4) { fprintf(stderr, "usage: watch <db> <address|hash160hex>\n"); return 2; }
    uint8_t h160[20];
    if (strlen(argv[3]) == 40) {
        size_t n; if (!idx_hex_to_bytes(argv[3], h160, 20, &n) || n != 20) { fprintf(stderr, "bad hash160 hex\n"); return 1; }
    } else {
        uint8_t ver, payload[32]; size_t plen;
        if (!idx_b58check_decode(argv[3], &ver, payload, sizeof payload, &plen) || plen != 20) {
            fprintf(stderr, "bad address (base58check)\n"); return 1;
        }
        memcpy(h160, payload, 20);
    }
    sqlite3 *db = idx_db_open(argv[2]); if (!db) { fprintf(stderr, "cannot open db\n"); return 1; }
    idx_db_watch_add(db, h160);
    char hh[41]; static const char *H = "0123456789abcdef";
    for (int i = 0; i < 20; i++) { hh[2*i] = H[h160[i]>>4]; hh[2*i+1] = H[h160[i]&15]; } hh[40] = 0;
    printf("watching %s (hash160 %s) — utxos recorded from the next synced block\n", argv[3], hh);
    idx_db_close(db); return 0;
}

// ── minimal Dogecoin P2P (self-contained; framing on protocol-sm SHA-256) ─────
static int write_all(int fd, const uint8_t *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, b + off, n - off);
        if (w <= 0) { if (w < 0 && errno == EINTR) continue; return 0; }
        off += (size_t)w;
    }
    return 1;
}
static int net_send(int fd, const uint8_t magic[4], const char *cmd, const uint8_t *payload, uint32_t len) {
    uint8_t hdr[24]; memset(hdr, 0, 24); memcpy(hdr, magic, 4);
    strncpy((char *)hdr + 4, cmd, 12);
    hdr[16] = (uint8_t)len; hdr[17] = (uint8_t)(len >> 8); hdr[18] = (uint8_t)(len >> 16); hdr[19] = (uint8_t)(len >> 24);
    uint8_t ck[32]; idx_sha256d(payload ? payload : (const uint8_t *)"", len, ck); memcpy(hdr + 20, ck, 4);
    // one buffered write: a large addr payload must not tear across two write()s
    // on a peer that reads a frame at a time (and write_all handles partials)
    if (!write_all(fd, hdr, 24)) return 0;
    if (len && !write_all(fd, payload, len)) return 0;
    return 1;
}
static int read_n(int fd, uint8_t *buf, size_t n, int timeout_ms) {
    size_t got = 0;
    while (got < n) {
        struct pollfd p = { fd, POLLIN, 0 };
        int pr = poll(&p, 1, timeout_ms); if (pr <= 0) return 0;
        ssize_t r = read(fd, buf + got, n - got); if (r <= 0) return 0; got += (size_t)r;
    }
    return 1;
}
static int net_recv(int fd, const uint8_t magic[4], char cmd_out[13], uint8_t **payload, uint32_t *len, int timeout_ms) {
    uint8_t hdr[24]; if (!read_n(fd, hdr, 24, timeout_ms)) return 0;
    if (memcmp(hdr, magic, 4) != 0) return -1;
    memcpy(cmd_out, hdr + 4, 12); cmd_out[12] = 0;
    uint32_t l = (uint32_t)hdr[16] | (uint32_t)hdr[17] << 8 | (uint32_t)hdr[18] << 16 | (uint32_t)hdr[19] << 24;
    if (l > 32 * 1024 * 1024) return -1;
    uint8_t *buf = malloc(l ? l : 1);
    if (l && !read_n(fd, buf, l, timeout_ms)) { free(buf); return 0; }
    *payload = buf; *len = l; return 1;
}
// Resolve `host` (name or literal) and connect to the first address that
// answers — a multi-A DNS seed's record set IS a failover list, so walk it.
// Each attempt is bounded (non-blocking connect + poll): a dead candidate must
// cost seconds, not a kernel-default 75 s stall per address.
static int net_connect(const char *host, uint16_t port) {
    char ps[8]; snprintf(ps, sizeof ps, "%u", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, ps, &hints, &res) != 0 || !res) return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai && !idx_sync_stop; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (r != 0 && errno == EINPROGRESS) {
            struct pollfd p = { fd, POLLOUT, 0 };
            int err = 0; socklen_t el = sizeof err;
            if (poll(&p, 1, 5000) == 1 &&
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) r = 0;
        }
        if (r == 0) { fcntl(fd, F_SETFL, fl); break; }
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}
// The connected socket's remote address as "ip:port" text (the concrete peer
// behind a seed name — what the last-good cache must remember).
static void net_peer_str(int fd, char *out, size_t cap) {
    struct sockaddr_storage ss; socklen_t sl = sizeof ss;
    char ip[INET6_ADDRSTRLEN] = "?"; unsigned port = 0;
    if (getpeername(fd, (struct sockaddr *)&ss, &sl) == 0) {
        if (ss.ss_family == AF_INET) {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
            inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof ip); port = ntohs(s4->sin_port);
        } else if (ss.ss_family == AF_INET6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
            inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof ip); port = ntohs(s6->sin6_port);
        }
    }
    snprintf(out, cap, "%s:%u", ip, port);
}
// Resolve a dial target to its first numeric address — no connect. Lets the
// per-host dedup and the serve-live check see THROUGH a hostname before paying
// a TCP dial + handshake to learn what it resolves to. 1 ok (out = numeric ip
// text), 0 = resolution failed (caller just proceeds to dial and finds out).
static int net_resolve_str(const char *host, char *out, size_t cap) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return 0;
    int ok = 0;
    for (struct addrinfo *ai = res; ai && !ok; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)ai->ai_addr)->sin_addr,
                      out, (socklen_t)cap); ok = 1;
        } else if (ai->ai_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
                      out, (socklen_t)cap); ok = 1;
        }
    }
    freeaddrinfo(res);
    return ok;
}
static void put_varint(uint8_t *b, int *o, uint64_t v) { if (v < 0xFD) b[(*o)++] = (uint8_t)v; else if (v <= 0xFFFF) { b[(*o)++] = 0xFD; b[(*o)++] = v & 0xff; b[(*o)++] = (v >> 8) & 0xff; } else { b[(*o)++] = 0xFE; for (int i = 0; i < 4; i++) b[(*o)++] = (v >> (8*i)) & 0xff; } }

// ── self-connect guard (Bitcoin/Dogecoin Core's version-nonce trick) ─────────
// This node is (or can be) its own seed: the seed hostname resolves to our own
// address, so both the sync thread and the serve thread may dial themselves. We
// stamp one per-process random nonce into every version we send; a version that
// echoes it back means the peer is us. pthread_once so the sync and serve
// threads agree on the same nonce.
static uint64_t g_self_nonce = 0;
static void self_nonce_gen(void) {
    while (!g_self_nonce)                                             // never 0 (0 = "unset")
        if (getentropy(&g_self_nonce, sizeof g_self_nonce) != 0) g_self_nonce = (uint64_t)time(NULL);
}
static uint64_t self_nonce(void) {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, self_nonce_gen);
    return g_self_nonce;
}
// The version nonce sits at a fixed payload offset: version(4)+services(8)+
// timestamp(8)+addr_recv(26)+addr_from(26) = 72. Returns 0 if too short.
static int ver_nonce(const uint8_t *pl, uint32_t pln, uint64_t *out) {
    const uint32_t off = 4 + 8 + 8 + 26 + 26;
    if (pln < off + 8) return 0;
    uint64_t n = 0; for (int i = 0; i < 8; i++) n |= (uint64_t)pl[off + i] << (8 * i);
    *out = n; return 1;
}
// Our own external IPv4, learned from a real peer's version.addr_recv (the ip
// THEY dialed us on). Written by whichever thread first handshakes a genuine
// peer, read by the serve dial loop to skip a seed that points back at us even
// when the dial can't complete (no NAT hairpin → no handshake → the nonce check
// can't fire). Best-effort cross-thread hint; a torn read just costs one extra
// dial attempt.
static char g_self_ip[INET_ADDRSTRLEN] = "";
// Record our external ip from a received version payload, if it carries a plausible
// non-local IPv4 in addr_recv (0xFFFF-mapped at offset 38, quad at 40).
static void learn_self_ip(const uint8_t *pl, uint32_t pln) {
    if (pln < 46 || pl[38] != 0xFF || pl[39] != 0xFF) return;
    unsigned a = pl[40];
    if (!a || a == 127 || a == 10) return;
    snprintf(g_self_ip, sizeof g_self_ip, "%u.%u.%u.%u", pl[40], pl[41], pl[42], pl[43]);
}
// True when `host` resolves to the IPv4 we advertise as ourselves. `self` is the
// serve loop's own learned addr ("ip:port", from an inbound peer); if it's NULL
// or empty we fall back to g_self_ip (learned by whichever thread first reached
// a real peer). This catches a seed that points back at us even when the dial
// can't complete — no NAT hairpin means no handshake, so the version-nonce check
// can't fire. A no-op until one of the two has been learned.
static int host_is_self(const char *host, const char *self) {
    char sip[64] = "";
    if (self && *self) { snprintf(sip, sizeof sip, "%s", self); char *c = strrchr(sip, ':'); if (c) *c = 0; }
    else if (g_self_ip[0]) snprintf(sip, sizeof sip, "%s", g_self_ip);
    else return 0;
    struct addrinfo hints, *res = NULL; memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return 0;
    int match = 0;
    for (struct addrinfo *ai = res; ai && !match; ai = ai->ai_next)
        if (ai->ai_family == AF_INET) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, ip, sizeof ip);
            if (!strcmp(ip, sip)) match = 1;
        }
    freeaddrinfo(res); return match;
}

// Cheap self-test for a harvested "ip:port" literal — plain compare against the
// ip we advertise, no resolver (addr_harvest runs per gossiped entry, up to
// 1000 an addr message, on both threads). Port-insensitive on purpose, same as
// host_is_self: our own host is our own host whichever port it names.
static int addr_is_self(const char *addr) {
    if (!g_self_ip[0] || !addr) return 0;
    size_t n = strlen(g_self_ip);
    return !strncmp(addr, g_self_ip, n) && (addr[n] == ':' || addr[n] == '\0');
}

static int p2p_handshake(int fd, const uint8_t magic[4], int64_t our_height) {
    uint8_t v[256]; int o = 0;
    for (int i = 0; i < 4; i++) v[o++] = (70015 >> (8*i)) & 0xff;     // version
    for (int i = 0; i < 8; i++) v[o++] = 0;                          // services
    int64_t now = (int64_t)time(NULL); for (int i = 0; i < 8; i++) v[o++] = (now >> (8*i)) & 0xff;  // timestamp
    memset(v + o, 0, 26); o += 26;                                   // addr_recv
    memset(v + o, 0, 26); o += 26;                                   // addr_from
    uint64_t sn = self_nonce();                                      // nonce (self-connect guard)
    for (int i = 0; i < 8; i++) v[o++] = (uint8_t)(sn >> (8*i));
    size_t ual = strlen(idx_sync_agent); if (ual > 100) ual = 100;   // user-agent: the
    v[o++] = (uint8_t)ual;                                           // "/pepenet-…/" subver is
    memcpy(v + o, idx_sync_agent, ual); o += (int)ual;               // the mesh's discovery mark
    for (int i = 0; i < 4; i++) v[o++] = (our_height >> (8*i)) & 0xff; // start_height
    v[o++] = 1;                                                      // relay: we accept tx invs (mempool)
    if (!net_send(fd, magic, "version", v, (uint32_t)o)) return 0;
    // exchange until we see verack
    int got_verack = 0, sent_verack = 0;
    for (int i = 0; i < 10; i++) {
        char cmd[13]; uint8_t *pl; uint32_t pl_len;
        int r = net_recv(fd, magic, cmd, &pl, &pl_len, 8000); if (r != 1) { if (r == -1) continue; return got_verack && sent_verack; }
        if (!strcmp(cmd, "version")) {
            uint64_t vn;                                 // did we just dial ourselves?
            if (ver_nonce(pl, pl_len, &vn) && vn == self_nonce()) { free(pl); return 2; }
            learn_self_ip(pl, pl_len);                   // the ip THEY see us as → our external addr
            net_send(fd, magic, "verack", NULL, 0); sent_verack = 1;
            // version.start_height: the peer's declared chain height — the wire's
            // only am-I-caught-up signal (a getblocks at tip is answered with
            // silence). Exported for embedding hosts (indexer.h).
            if (pl_len >= 12) {                          // services (crawl classifier)
                uint64_t sv = 0; for (int b = 0; b < 8; b++) sv |= (uint64_t)pl[4 + b] << (8 * b);
                idx_sync_peer_services = sv;
            }
            uint64_t off = 4 + 8 + 8 + 26 + 26 + 8, ua;  // fields before user_agent
            int ok = pl_len > off;
            ua = ok ? pl[off++] : 0;
            if (ok && ua == 0xFD) { ok = pl_len >= off + 2; if (ok) { ua = pl[off] | ((uint64_t)pl[off+1] << 8); off += 2; } }
            else if (ua > 0xFD) ok = 0;                  // 4/8-byte UA length: no real peer
            if (ok && pl_len >= off + ua + 4) {
                size_t an = ua < sizeof idx_sync_peer_agent - 1 ? ua : sizeof idx_sync_peer_agent - 1;
                memcpy((char *)idx_sync_peer_agent, pl + off, an);
                ((char *)idx_sync_peer_agent)[an] = 0;   // peer subver — the crawl's classifier
                off += ua;
                int32_t ph = (int32_t)((uint32_t)pl[off] | ((uint32_t)pl[off+1] << 8) |
                                       ((uint32_t)pl[off+2] << 16) | ((uint32_t)pl[off+3] << 24));
                if (ph > 0) idx_sync_peer_height = ph;
            }
        }
        else if (!strcmp(cmd, "verack")) got_verack = 1;
        else if (!strcmp(cmd, "ping")) net_send(fd, magic, "pong", pl, pl_len);
        free(pl);
        if (got_verack && sent_verack) return 1;
    }
    return got_verack && sent_verack;
}

volatile int idx_sync_stop = 0;                 // embedding hosts only (indexer.h)
volatile int idx_self_seed = 0;                 // set when a seed dial loops home (indexer.h)
volatile int64_t idx_sync_peer_height = 0;      // embedding hosts only (indexer.h)
const char *idx_sync_agent = IDX_DNET_MARK "indexer:0.1/";   // hosts override (indexer.h)
volatile char idx_sync_peer_agent[128] = "";    // this pass's peer subver (indexer.h)
volatile uint64_t idx_sync_peer_services = 0;   // this pass's peer services (indexer.h)

// ── peer candidates + addr harvest ────────────────────────────────────────────
// "host[:port]" → host copy + port (dflt when absent). Bare IPv6 not supported
// here — harvested/dialed text addrs are IPv4 or hostnames.
static void peer_split(const char *s, char *host, size_t hcap, uint16_t *port, uint16_t dflt) {
    snprintf(host, hcap, "%s", s);
    *port = dflt;
    char *c = strrchr(host, ':');
    if (c && c[1] && strspn(c + 1, "0123456789") == strlen(c + 1)) { *c = 0; *port = (uint16_t)atoi(c + 1); }
}
static int cand_add(char (*cand)[80], int n, int max, const char *s) {
    if (!s || !*s || n >= max) return n;
    for (int i = 0; i < n; i++) if (!strcmp(cand[i], s)) return n;
    snprintf(cand[n], 80, "%s", s);
    return n + 1;
}
// addr payload: varint count, then per entry time(4) services(8LE) ip(16) port(2BE).
// Harvest routable IPv4 entries into the peers table — the failover pool the next
// pass draws on, and slice 2's crawl frontier. Bounds-checked like inv (peer bytes).
// `dnet`: this came over dnaddr (a pepenet peer vouched for these) → mark the rows
// so the overlay dialer re-seats from them; plain chain addr passes dnet=0.
static void addr_harvest(sqlite3 *db, const uint8_t *pl, uint32_t pl_len, int dnet) {
    if (!db || pl_len < 1) return;
    uint32_t po = 0; uint64_t cnt = pl[po++];
    if (cnt == 0xFD) { if (pl_len < 3) return; cnt = pl[po] | ((uint64_t)pl[po+1] << 8); po += 2; }
    else if (cnt >= 0xFE) return;
    if (cnt > 1000) cnt = 1000;                  // MAX_ADDR_TO_SEND
    int64_t now = (int64_t)time(NULL);
    for (uint64_t i = 0; i < cnt && po + 30 <= pl_len; i++, po += 30) {
        const uint8_t *e = pl + po;
        int64_t svc = 0; for (int b = 0; b < 8; b++) svc |= (int64_t)e[4 + b] << (8 * b);
        const uint8_t *ip = e + 12;
        static const uint8_t v4map[12] = { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF };
        if (memcmp(ip, v4map, 12) != 0) continue;                    // IPv4 only for now
        uint8_t a = ip[12], b2 = ip[13];
        if (a == 0 || a == 127 || a == 10 || (a == 172 && b2 >= 16 && b2 <= 31) ||
            (a == 192 && b2 == 168) || (a == 169 && b2 == 254)) continue;   // unroutable
        uint16_t port = (uint16_t)(e[28] << 8 | e[29]);
        if (!port) continue;
        char addr[80]; snprintf(addr, sizeof addr, "%u.%u.%u.%u:%u", a, b2, ip[14], ip[15], port);
        // never harvest ourselves: we self-announce, so our own addr is gossiped
        // straight back at us and would otherwise land in the dial pool (as a
        // dnet=1 vouch off dnaddr, which the overlay dialer then seats).
        if (addr_is_self(addr)) continue;
        if (dnet) idx_db_peer_dnet_note(db, addr, svc, now);
        else      idx_db_peer_note(db, addr, svc, now);
    }
}

// ── block validation (peer bytes are hostile until proven) ───────────────────
// Stateless: tx-merkle root (meta.merkle_ok from the parse) + idx_pow_check
// (target sanity, scrypt work, full AuxPoW). Contextual: the Digishield-expected
// nBits and the median-time-past rule, anchored on the blocks table with the
// profile's pinned checkpoint header standing in for the two heights below a
// fresh db's start. Context rows with bits==0 (written before the column
// existed) skip the nBits equality for that one block — the work check stands.
static int block_validate(sqlite3 *db, const Coin *coin, int64_t pos,
                          const uint8_t *raw, size_t len, char *why, size_t cap) {
    if (!coin->powlimit) return 1;               // test profile: fixture chains
    IdxBlockMeta m;
    if (!idx_parse_block(raw, len, &m, NULL, NULL)) { snprintf(why, cap, "unparseable"); return 0; }
    if (!m.merkle_ok) { snprintf(why, cap, "tx merkle mismatch"); return 0; }
    PowParams pp = { coin->powlimit, coin->aux_chain_id };
    if (!idx_pow_check(raw, len, &pp, why, cap)) return 0;
    int64_t pt = 0, ppt = 0; uint32_t pbits = 0;
    if (pos - 1 == coin->start) { pt = coin->start_time; pbits = coin->start_bits; }
    else idx_db_block_hdr(db, pos - 1, &pt, &pbits);
    if (pos - 2 == coin->start) ppt = coin->start_time;
    else if (pos - 2 == coin->start - 1) ppt = coin->start_prev_time;
    else idx_db_block_hdr(db, pos - 2, &ppt, NULL);
    if (pbits && pt && ppt) {
        uint32_t want = idx_pow_next_bits(pbits, pt, ppt, coin->powlimit);
        if (m.bits != want) {
            snprintf(why, cap, "nBits 0x%08x != Digishield-expected 0x%08x", m.bits, want);
            return 0;
        }
    }
    int64_t times[12]; int n = idx_db_block_times(db, pos, times);
    if (n < 11 && pos - n - 1 == coin->start) times[n++] = coin->start_time;
    if (n < 11 && pos - n - 1 == coin->start - 1) times[n++] = coin->start_prev_time;
    if (n) {
        for (int i = 1; i < n; i++) {            // insertion sort, n ≤ 11
            int64_t v = times[i]; int j = i - 1;
            while (j >= 0 && times[j] > v) { times[j + 1] = times[j]; j--; }
            times[j + 1] = v;
        }
        if ((int64_t)m.time <= times[n / 2]) {
            snprintf(why, cap, "time %u <= median-time-past %lld", m.time, (long long)times[n / 2]);
            return 0;
        }
    }
    return 1;
}

// ── most-work chain selection (cumulative-work fork rule) ─────────────────────
// The forward sync is blocks-first (getblocks/inv/block), but a REORG must not be
// first-valid-peer-wins: a valid-but-lighter fork must never rewrite an
// established chain. When a peer serves a block extending an ancestor, we weigh
// its whole branch by cumulative work — fetched cheaply as headers — against ours
// above the fork, and only reorg if it is strictly heavier.
typedef struct {
    int64_t  h;              // height of the last accepted branch header
    uint8_t  prev_hash[32];  // its hash — the next header must chain to this
    int64_t  prev_time, prevprev_time;
    uint32_t prev_bits;
    uint8_t  work[32];       // Σ proof-of-work of accepted branch headers
    int      n;
} BranchCtx;

// Seed the walk at the fork point, sourcing the retarget context (fork_h and its
// parent's time/bits) exactly as block_validate does — checkpoint stand-ins for
// the two heights below a fresh db's start.
static void branch_seed(BranchCtx *bc, const Coin *coin, sqlite3 *db,
                        int64_t fork_h, const uint8_t fork_hash[32]) {
    memset(bc, 0, sizeof *bc);
    bc->h = fork_h; memcpy(bc->prev_hash, fork_hash, 32);
    int64_t pt = 0, ppt = 0; uint32_t pbits = 0;
    if (fork_h == coin->start) { pt = coin->start_time; pbits = coin->start_bits; }
    else idx_db_block_hdr(db, fork_h, &pt, &pbits);
    if (fork_h - 1 == coin->start) ppt = coin->start_time;
    else if (fork_h - 1 == coin->start - 1) ppt = coin->start_prev_time;
    else idx_db_block_hdr(db, fork_h - 1, &ppt, NULL);
    bc->prev_time = pt; bc->prevprev_time = ppt; bc->prev_bits = pbits;
}

// Validate + weigh one `headers` message onto bc. Each element is header[+auxpow]
// then a tx-count varint (0 in a headers message). Same checks Core applies to a
// header on a candidate chain — linkage, PoW (scrypt/auxpow ≤ target), and the
// per-block Digishield nBits — so a branch we accept as heavier is one whose
// blocks will also validate when we download them. Returns headers accepted, or
// -1 on the first invalid one.
static int branch_weigh(BranchCtx *bc, const Coin *coin, sqlite3 *db,
                        const uint8_t *pl, uint32_t pl_len, char *why, size_t cap) {
    (void)db;
    PowParams pp = { coin->powlimit, coin->aux_chain_id };
    if (pl_len < 1) return 0;
    int po = 0; uint64_t cnt = pl[po++];
    if (cnt == 0xFD) { if (pl_len < 3) return 0; cnt = pl[po] | (pl[po+1] << 8); po += 2; }
    else if (cnt >= 0xFE) { snprintf(why, cap, "headers count too large"); return -1; }
    int accepted = 0;
    for (uint64_t i = 0; i < cnt; i++) {
        if (po + 80 > (int)pl_len) { snprintf(why, cap, "headers truncated"); return -1; }
        const uint8_t *hdr = pl + po;
        if (memcmp(hdr + 4, bc->prev_hash, 32) != 0) { snprintf(why, cap, "branch header %d off-chain", accepted); return -1; }
        size_t span = 0;
        if (!idx_pow_check2(hdr, pl_len - po, &pp, &span, why, cap)) return -1;
        uint32_t bits = (uint32_t)hdr[72] | (uint32_t)hdr[73] << 8 | (uint32_t)hdr[74] << 16 | (uint32_t)hdr[75] << 24;
        if (bc->prev_bits && bc->prev_time && bc->prevprev_time) {
            uint32_t want = idx_pow_next_bits(bc->prev_bits, bc->prev_time, bc->prevprev_time, coin->powlimit);
            if (bits != want) { snprintf(why, cap, "branch nBits 0x%08x != Digishield 0x%08x at %lld", bits, want, (long long)(bc->h + 1)); return -1; }
        }
        int64_t t = (uint32_t)hdr[68] | (uint32_t)hdr[69] << 8 | (uint32_t)hdr[70] << 16 | (uint32_t)hdr[71] << 24;
        uint8_t hh[32]; idx_sha256d(hdr, 80, hh);
        uint8_t w[32]; idx_pow_work(bits, w); idx_pow_work_add(bc->work, w);
        bc->prevprev_time = bc->prev_time; bc->prev_time = t; bc->prev_bits = bits;
        memcpy(bc->prev_hash, hh, 32); bc->h++; bc->n++; accepted++;
        po += (int)span;                                   // header + auxpow
        if (po >= (int)pl_len) break;
        uint8_t tc = pl[po++];                             // tx-count varint (0 here)
        if (tc == 0xFD) po += 2; else if (tc == 0xFE) po += 4; else if (tc == 0xFF) po += 8;
    }
    return accepted;
}

// 1 = the peer's branch is strictly heavier than ours above fork_h (reorg),
// 0 = not heavier / unweighable (keep our chain), -1 = branch invalid (drop peer).
static int branch_outweighs(int fd, const Coin *coin, sqlite3 *db,
                            int64_t fork_h, const uint8_t fork_hash[32],
                            int64_t our_height, char *why, size_t cap) {
    // OUR cumulative work above the fork. A block with bits==0 (a legacy db from
    // before the PoW column) is unweighable → refuse the reorg: an established
    // chain is never rewritten from history we cannot weigh. A re-sync populates
    // bits and turns most-work reorgs back on.
    uint8_t our_work[32]; memset(our_work, 0, 32);
    for (int64_t h = fork_h + 1; h <= our_height; h++) {
        int64_t t; uint32_t bits;
        if (!idx_db_block_hdr(db, h, &t, &bits) || bits == 0) {
            snprintf(why, cap, "our block %lld has no recorded work — re-sync to enable most-work reorgs", (long long)h);
            return 0;
        }
        uint8_t w[32]; idx_pow_work(bits, w); idx_pow_work_add(our_work, w);
    }
    BranchCtx bc; branch_seed(&bc, coin, db, fork_h, fork_hash);
    for (int page = 0; page < 64 && !idx_sync_stop; page++) {  // ≤128k headers
        uint8_t gh[4 + 3 + 3*32]; int o = 0;
        for (int i = 0; i < 4; i++) gh[o++] = (70015 >> (8*i)) & 0xff;
        put_varint(gh, &o, 2);
        memcpy(gh + o, bc.prev_hash, 32); o += 32;         // locator: the branch cursor
        memcpy(gh + o, coin->start_hash, 32); o += 32;     // + the checkpoint anchor
        memset(gh + o, 0, 32); o += 32;                    // hash_stop
        net_send(fd, coin->magic, "getheaders", gh, (uint32_t)o);
        char cmd[13]; uint8_t *pl = NULL; uint32_t pl_len = 0; int got = 0;
        // Drain until the `headers` reply. This weigh runs INSIDE the block
        // receive loop, right after a getdata for a whole inv batch (≤600
        // blocks) — so the peer streams that block backlog ahead of the headers
        // it queues for our getheaders. An 8-message window gave up inside the
        // flood and returned "not heavier", wedging a node on a minority fork
        // forever (the branch it declined was the majority chain). The real
        // timeout still bounds a dead peer: net_recv returns 0 on a 15 s stall,
        // taking the `r != 1` exit below. Cap well above one batch as a
        // junk-flood backstop.
        for (int tries = 0; tries < 4096 && !got && !idx_sync_stop; tries++) {
            int r = net_recv(fd, coin->magic, cmd, &pl, &pl_len, 15000);
            if (r != 1) { if (r == -1) continue; return 0; }         // dead/timeout → keep ours
            if (!strcmp(cmd, "ping")) { net_send(fd, coin->magic, "pong", pl, pl_len); free(pl); continue; }
            if (!strcmp(cmd, "headers")) { got = 1; break; }
            free(pl);                                                // drop interleaved inv/addr/block backlog
        }
        if (!got) return 0;
        int n = branch_weigh(&bc, coin, db, pl, pl_len, why, cap);
        free(pl);
        if (n < 0) return -1;
        if (idx_pow_work_cmp(bc.work, our_work) > 0) return 1;       // already heavier
        if (n < 2000) break;                                        // branch ended, not heavier
    }
    return idx_pow_work_cmp(bc.work, our_work) > 0 ? 1 : 0;
}

// weigh <coin> <headers-file> — dev/test: validate + weigh a raw `headers`
// message body as a branch off the profile checkpoint (Digishield anchored on
// the pinned start header). Prints the accepted count + cumulative work, or the
// rejection reason. Lets the most-work validation pipeline be tested against
// real merged-mined headers pulled from a live node (no mining needed).
static int cmd_weigh(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: weigh <coin> <headers-file>\n"); return 2; }
    const Coin *coin = coin_by_name(argv[2]); if (!coin) { fprintf(stderr, "unknown coin %s\n", argv[2]); return 2; }
    if (!coin->powlimit) { fprintf(stderr, "coin %s has PoW validation off\n", coin->name); return 2; }
    size_t len; uint8_t *pl = read_file(argv[3], &len);
    if (!pl) { fprintf(stderr, "cannot read %s\n", argv[3]); return 1; }
    BranchCtx bc; branch_seed(&bc, coin, NULL, coin->start, coin->start_hash);
    char why[160] = "";
    int n = branch_weigh(&bc, coin, NULL, pl, (uint32_t)len, why, sizeof why);
    free(pl);
    if (n < 0) { fprintf(stderr, "REJECTED after %d accepted (at height %lld): %s\n",
                         bc.n, (long long)(bc.h + 1), why); return 1; }
    char wh[65]; static const char *H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { wh[2*i] = H[bc.work[31-i] >> 4]; wh[2*i+1] = H[bc.work[31-i] & 15]; }
    wh[64] = 0;
    int allzero = 1; for (int i = 0; i < 32; i++) if (bc.work[i]) { allzero = 0; break; }
    printf("accepted %d headers off %s checkpoint %lld, cumulative work 0x%s\n",
           n, coin->name, (long long)coin->start, wh);
    return allzero ? 1 : 0;   // zero work on a non-empty accept = a bug
}

// Parity clock for the sync pass's skip-socket gate: the last wall time we had
// hard evidence of being at the network tip (a staged fold, or a socket pass
// measuring height ≥ the peer's claim). In-process across passes; the fresh
// value at boot doubles as the boot grace window.
#define SYNC_PARITY_GRACE_S 900
static time_t s_parity;

static int cmd_sync(int argc, char **argv) {
    // sync <coin> <db> [peers] [activation] — peers: comma-separated host[:port]
    // list tried first (hostnames ok), or "auto" for cache+seeds only.
    if (argc < 4) { fprintf(stderr, "usage: sync <doge|pep|testnet|regtest> <db> [peers=127.0.0.1|auto] [activation]\n"); return 2; }
    const Coin *coin = coin_by_name(argv[2]); if (!coin) { fprintf(stderr, "unknown coin %s\n", argv[2]); return 2; }
    const char *dbpath = argv[3]; const char *ip = argc > 4 ? argv[4] : "127.0.0.1";
    sqlite3 *db = idx_db_open(dbpath); if (!db) { fprintf(stderr, "cannot open %s\n", dbpath); return 1; }
    // A stored activation always wins (changing it mid-state would fork the fold);
    // the CLI value only seeds a fresh DB.
    int64_t cli_act = argc > 5 ? strtoll(argv[5], NULL, 10) : coin->activation;
    int64_t activation = idx_db_get_activation(db, cli_act); idx_db_set_activation(db, activation);
    if (argc > 5 && activation != cli_act)
        fprintf(stderr, "note: db pins activation %lld; ignoring CLI %lld\n", (long long)activation, (long long)cli_act);
    SmState *s = sm_new((uint64_t)activation);
    OracleFeed *oracle = oracle_new();
    oracle_set_subsidy(oracle, coin->subsidy); idx_db_set_subsidy(db, coin->subsidy);   // profile → feed + db pin
    idx_db_load_state(db, s); idx_db_oracle_warm(db, oracle); oracle_set_subsidy(oracle, idx_db_get_subsidy(db, SUBSIDY_10K));
    // Fresh DB: stand on the profile's start checkpoint (never folded itself) so the
    // peer serves start+1 as start+1 — heights in the fold are real chain heights.
    int64_t height = 0; uint8_t tip[32];
    if (!idx_db_load_sync(db, &height, tip)) {
        height = coin->start; memcpy(tip, coin->start_hash, 32);
        idx_db_epochs_mark(db, 0);   // complete-history DB: epoch coverage from genesis
    }
    // Crash-consistency: the loaded fold state is the projection, at proj_height. If a
    // prior run died after advancing the (autocommitted) sync height past the last
    // committed projection, resume from proj_height and re-fold the gap — never from a
    // height ahead of the state, which would silently skip those blocks' actions.
    int64_t proj_h = idx_db_projected_height(db);
    if (proj_h >= 0 && proj_h < height) {
        fprintf(stderr, "recovery: sync height %lld is ahead of the projection %lld (prior crash) — resuming from %lld\n",
                (long long)height, (long long)proj_h, (long long)proj_h);
        height = proj_h;
        if (height <= coin->start) { height = coin->start; memcpy(tip, coin->start_hash, 32); }
        else if (!idx_db_block_get(db, height, tip)) memcpy(tip, coin->start_hash, 32);
        idx_db_save_sync(db, height, tip);
    }
    // One-time wallet re-walk ("wallet_rewalk_v1"): earlier builds' rollback
    // replay re-INSERTed watched outputs with spent_height=NULL (OR REPLACE),
    // so an accepted reorg could resurrect an output whose spend sat in a
    // non-carrier block — a block the replay substrate never stored, leaving
    // nothing local to repair from. Heal by re-walking the chain: roll the fold
    // back to just below the oldest unspent watched output and let this same
    // pass re-download and refold from there — utxo_put now preserves standing
    // rows and the refold re-marks every lost spend, so the walk converges on
    // the true balance. Runs once per db; a no-wallet db just sets the flag.
    if (!idx_db_flag_get(db, "wallet_rewalk_v1")) {
        int64_t mh = idx_db_utxo_min_unspent(db);
        int64_t to = mh > 0 ? mh - 1 : -1;
        if (to >= 0 && to < coin->start) to = coin->start;
        if (to >= 0 && to < height) {
            fprintf(stderr, "wallet re-walk: re-verifying spends over blocks %lld..%lld\n",
                    (long long)(to + 1), (long long)height);
            if (idx_sync_rollback(&s, db, oracle, activation, to)) {
                height = to;
                if (height <= coin->start) { height = coin->start; memcpy(tip, coin->start_hash, 32); }
                else if (!idx_db_block_get(db, height, tip)) memcpy(tip, coin->start_hash, 32);
                idx_db_save_sync(db, height, tip);
                idx_db_flag_set(db, "wallet_rewalk_v1");
            }   // rollback failure: leave the flag unset, retry next pass
        } else
            idx_db_flag_set(db, "wallet_rewalk_v1");
    }
    // The loaded state IS the projection at `height` (post-recovery). Seed the
    // fold cursor: sm_new starts cur_height at 0 and idx_db_load_state never
    // sets it, so a pass that connects nothing (fully synced, quiet window)
    // would stamp proj_height=0 at pass end — which the NEXT boot reads as a
    // crash gap and "recovers" a synced db all the way back to the checkpoint.
    s->cur_height = height;
    FoldCtx fc = { .s = s, .db = db, .oracle = oracle };
    fold_load_watch(&fc);
    // serve cache: the header chain + rolling block window, a separate aux db
    // (serve-<coin>.db) next to the fold db — populated as we connect blocks so
    // this node can answer getheaders/getdata for other pepenet peers.
    char serve_path[600];
    { const char *slash = strrchr(dbpath, '/');
      if (slash) snprintf(serve_path, sizeof serve_path, "%.*s/serve-%s.db",
                          (int)(slash - dbpath), dbpath, coin->name);
      else snprintf(serve_path, sizeof serve_path, "serve-%s.db", coin->name); }
    fc.serve = serve_store_open(serve_path);

    // ── phase 0: fold off the stage (sync-over-one-connection) ────────────────
    // The serve thread getdatas every unknown block inv on its (mesh) conns
    // into blockstage; rows that extend our tip fold HERE, through the same
    // validation as socket blocks. A node at tip thus follows the chain over
    // its one persistent connection, and — when the mesh's claimed best height
    // says we're caught up — this pass ends without opening a socket at all.
    // The socket ladder below remains the path for initial sync, catch-up
    // gaps deeper than the stage, and every reorg.
    int64_t stage_folded = 0;
    if (fc.serve) {
        uint8_t sh[32], *sraw; size_t slen; char swhy[128];
        int guard = 0;   // bound: a stage_del lost to sqlite contention must not spin the pass
        while (!idx_sync_stop && guard++ < 512 &&
               serve_store_stage_next(fc.serve, tip, sh, &sraw, &slen)) {
            if (!block_validate(db, coin, height + 1, sraw, slen, swhy, sizeof swhy)) {
                fprintf(stderr, "staged block for height %lld invalid: %s — dropping\n",
                        (long long)(height + 1), swhy);
                serve_store_stage_del(fc.serve, sh); free(sraw);
                continue;                           // another stage row may chain here
            }
            int ok = connect_block(&fc, height + 1, sraw, slen);
            serve_store_stage_del(fc.serve, sh); free(sraw);
            if (!ok) continue;
            height++; stage_folded++;
            { int64_t hh; idx_db_load_sync(db, &hh, tip); }   // refresh tip hash
        }
        if (stage_folded)
            fprintf(stderr, "folded %lld staged block(s) off the mesh line — height %lld\n",
                    (long long)stage_folded, (long long)height);

        // stage-side REORG (one connection, no socket): unchainable stage rows
        // may be the winning branch of an orphan race, delivered over the
        // standing conn by push/pull. If they tie to a recent ancestor and
        // chain contiguously in the stage, weigh them EXACTLY like the socket
        // path weighs a peer branch — branch_weigh per staged block's
        // header[+auxpow]: linkage, PoW, Digishield — and only a strictly
        // heavier branch rolls us back; the normal validate+fold then connects
        // it. A judged-lighter or invalid branch is deleted (never re-judged
        // every pass); anything unanchored just ages out of the stage.
        if (!idx_sync_stop && serve_store_stage_pending(fc.serve)) {
            int64_t fork_h = -1; uint8_t fh[32];
            { uint8_t ph[32], *praw; size_t plen;
              for (int64_t h = height - 1; h > height - 32 && h >= coin->start && fork_h < 0; h--)
                  if (idx_db_block_get(db, h, fh) &&
                      serve_store_stage_next(fc.serve, fh, ph, &praw, &plen)) {
                      free(praw);                       // probe only — re-read in the walk
                      fork_h = h;
                  } }
            if (fork_h >= 0) {
                uint8_t bhs[32][32]; uint8_t *raws[32]; size_t lens[32]; int bn = 0;
                uint8_t cur[32]; memcpy(cur, fh, 32);
                while (bn < 32 && serve_store_stage_next(fc.serve, cur, bhs[bn], &raws[bn], &lens[bn])) {
                    memcpy(cur, bhs[bn], 32); bn++;
                }
                int verdict = 0;                        // 1 reorg · -1 drop rows · 0 leave
                char bwhy[160] = "";
                if (bn > 0) {
                    uint8_t ours[32]; memset(ours, 0, 32); int weighable = 1;
                    for (int64_t h = fork_h + 1; h <= height && weighable; h++) {
                        int64_t t; uint32_t bits;
                        if (!idx_db_block_hdr(db, h, &t, &bits) || bits == 0) weighable = 0;
                        else { uint8_t w[32]; idx_pow_work(bits, w); idx_pow_work_add(ours, w); }
                    }
                    BranchCtx bc; branch_seed(&bc, coin, db, fork_h, fh);
                    int ok = weighable;
                    for (int i = 0; i < bn && ok; i++) {
                        // one staged block as a 1-element headers message:
                        // varint(1) + header[+auxpow] + tx-count… — branch_weigh
                        // reads exactly that prefix and ignores the tx bytes
                        uint8_t *one = malloc(1 + lens[i]);
                        if (!one) { ok = 0; break; }
                        one[0] = 1; memcpy(one + 1, raws[i], lens[i]);
                        if (branch_weigh(&bc, coin, db, one, (uint32_t)(1 + lens[i]),
                                         bwhy, sizeof bwhy) != 1) ok = 0;
                        free(one);
                    }
                    if (ok && idx_pow_work_cmp(bc.work, ours) > 0) verdict = 1;
                    else verdict = -1;                  // lighter, invalid, or unweighable
                }
                if (verdict == 1) {
                    fprintf(stderr, "reorg (mesh stage): branch at height %lld outweighs our tip %lld — rolling back\n",
                            (long long)fork_h, (long long)height);
                    if (!idx_sync_rollback(&s, db, oracle, activation, fork_h)) {
                        // state is not trustworthy past a failed replay — bail hard
                        fprintf(stderr, "rollback replay failed — aborting sync\n");
                        for (int i = 0; i < bn; i++) free(raws[i]);
                        serve_store_close(fc.serve); oracle_free(oracle); sm_free(s); idx_db_close(db);
                        return 1;
                    }
                    fc.s = s;
                    serve_store_prune_above(fc.serve, fork_h);
                    height = fork_h;
                    if (!idx_db_block_get(db, height, tip)) memcpy(tip, coin->start_hash, 32);
                    idx_db_save_sync(db, height, tip);
                    for (int i = 0; i < bn; i++) {
                        char rwhy[128];
                        int good = block_validate(db, coin, height + 1, raws[i], lens[i], rwhy, sizeof rwhy) &&
                                   connect_block(&fc, height + 1, raws[i], lens[i]);
                        serve_store_stage_del(fc.serve, bhs[i]);
                        if (!good) {
                            fprintf(stderr, "staged branch block for %lld refused: %s\n",
                                    (long long)(height + 1), rwhy);
                            break;
                        }
                        height++; stage_folded++;
                        { int64_t hh; idx_db_load_sync(db, &hh, tip); }
                    }
                    idx_db_project(db, s);
                } else if (verdict == -1) {
                    fprintf(stderr, "staged branch at %lld not heavier than tip %lld — dropping %d row(s)%s%s\n",
                            (long long)fork_h, (long long)height, bn,
                            bwhy[0] ? ": " : "", bwhy);
                    for (int i = 0; i < bn; i++) serve_store_stage_del(fc.serve, bhs[i]);
                }
                for (int i = 0; i < bn; i++) free(raws[i]);
            }
        }
    }
    if (stage_folded) idx_db_project(db, s);    // stage folds feed the projection
                                                // too — market/names must not lag
                                                // a pass that never opens a socket
    // At the mesh's claimed tip, recent parity evidence, and NOTHING left in
    // the stage we couldn't chain? Then there is nothing a socket could add.
    // Each guard closes its own stall:
    //  · stage_pending — an unchainable staged block is the winning side of an
    //    orphan race (its prev is our tip's PARENT) or a child whose parent's
    //    body got lost: our tip is suspect and only the socket path can weigh
    //    and reorg. The stage nudge already woke this pass seconds after that
    //    block arrived, so recovery is immediate — never parked behind a clock.
    //  · the parity clock — claimed heights are captured at handshake and go
    //    stale on a long-lived conn. Parity evidence = a staged fold, or a
    //    socket pass that measured height ≥ the peer's claim; at process start
    //    it winds up fresh (boot grace) so the serve plane's per-minute mesh
    //    PULL (getblocks on the standing conn) proves itself before this pass
    //    ever burns a transient socket. Only a quiet spell past the grace —
    //    many minutes without a block on a 1-min chain — forces a re-measure.
    if (stage_folded || !s_parity) s_parity = time(NULL);
    { int64_t best = idx_serve_best_height();
      if (best > 0 && height >= best &&
          !serve_store_stage_pending(fc.serve) &&
          time(NULL) - s_parity < SYNC_PARITY_GRACE_S) {
          serve_store_close(fc.serve); oracle_free(oracle); sm_free(s); idx_db_close(db);
          return 0;
      } }

    idx_sync_peer_height = 0;    // per-pass: a dead peer must not inherit the last answer
    idx_sync_peer_agent[0] = 0; idx_sync_peer_services = 0;
    // Candidates, in trust order: the explicit CLI peers ("auto" = none) → the
    // cached last-good + harvested NODE_NETWORK peers → the chain's DNS seeds.
    // First candidate that connects AND handshakes wins; the concrete address it
    // resolved to is cached so the next pass leads with a proven peer even if
    // every seed has rotted.
    char cand[24][80]; int nc = 0;
    if (strcmp(ip, "auto") != 0) {
        char list[256]; snprintf(list, sizeof list, "%s", ip);
        for (char *sv, *t = strtok_r(list, ",", &sv); t; t = strtok_r(NULL, ",", &sv))
            nc = cand_add(cand, nc, 24, t);
    }
    { char cached[8][80]; int n = idx_db_peers_best(db, cached, 8);
      for (int i = 0; i < n; i++) nc = cand_add(cand, nc, 24, cached[i]); }
    for (int i = 0; coin->seeds[i]; i++) nc = cand_add(cand, nc, 24, coin->seeds[i]);
    int fd = -1; char picked[80] = "";
    int fb_fd = -1; char fb_picked[80] = "";      // limited peer, held as last resort
    int64_t fb_h = 0, fb_svc = 0; char fb_agent[128] = "";
    for (int i = 0; i < nc && fd < 0 && !idx_sync_stop; i++) {
        char host[80]; uint16_t port;
        peer_split(cand[i], host, sizeof host, &port, coin->port);
        // once the first pass has proven the seed is us, stop burning a full
        // dial + handshake on it every pass — skip known-self candidates up front
        if (idx_self_seed && host_is_self(host, NULL)) continue;
        // ONE CONNECTION PER PEER, no exceptions: a peer the serve plane owns
        // (live conn or seat) is reached ONLY over that standing line — tip
        // follow, catch-up and reorgs all ride the stage (push + locator pull
        // + stage-side reorg), so a second socket buys nothing but the exact
        // duplicate-connection noise this design exists to kill. Skip in both
        // name and resolved form. Candidates we hold no conn to (archive
        // chain nodes) stay fair game — deep catch-up beyond a limited peer's
        // window can only come from them anyway.
        { char srip[80];
          if (idx_serve_peer_held(host) ||
              (net_resolve_str(host, srip, sizeof srip) && idx_serve_peer_held(srip)))
              continue; }
        fd = net_connect(host, port);
        if (fd < 0) { fprintf(stderr, "  %s:%u unreachable\n", host, port); continue; }
        int hr = p2p_handshake(fd, coin->magic, height);
        if (hr == 2) {   // the seed hostname points back at us — skip, use a real peer
            fprintf(stderr, "  %s:%u is ourselves — skipping self-seed\n", host, port);
            idx_self_seed = 1;
            close(fd); fd = -1; continue;
        }
        if (!hr) {
            fprintf(stderr, "  %s:%u handshake failed\n", host, port);
            close(fd); fd = -1; continue;
        }
        if (idx_sync_peer_height > 0) idx_db_set_peer_height(db, idx_sync_peer_height);
        net_peer_str(fd, picked, sizeof picked);
        idx_db_peer_seen(db, picked, (int64_t)idx_sync_peer_services,
                         (const char *)idx_sync_peer_agent, (int64_t)time(NULL));
        // NODE_NETWORK gate (Core's limited-peer rule): a peer without service
        // bit 0 keeps only the last SERVE_BLOCK_WINDOW blocks (the pepenet
        // seed advertises NODE_NETWORK_LIMITED). If our fold is deeper behind
        // its claimed tip than that window, it cannot feed us — its answer to
        // our getblocks is pure silence, which reads as "caught up" and would
        // wedge this node at its checkpoint forever: connected, handshaken,
        // idle. Hold ONE such peer as a last resort and keep hunting for a
        // full-archive peer (the cached pool and the chain's DNS seeds).
        if (idx_sync_peer_height - height > SERVE_BLOCK_WINDOW &&
            !(idx_sync_peer_services & 1)) {
            fprintf(stderr, "  %s serves only recent blocks and we are %lld behind — seeking an archive peer\n",
                    picked, (long long)(idx_sync_peer_height - height));
            if (fb_fd < 0) {
                fb_fd = fd; snprintf(fb_picked, sizeof fb_picked, "%s", picked);
                fb_h = idx_sync_peer_height; fb_svc = (int64_t)idx_sync_peer_services;
                snprintf(fb_agent, sizeof fb_agent, "%s", (const char *)idx_sync_peer_agent);
            } else close(fd);
            fd = -1; continue;
        }
    }
    if (fd < 0 && fb_fd >= 0 && !idx_sync_stop) {
        // nothing better answered — take what the limited peer can give. While
        // we are deep behind that is nothing (the pass ends idle and the next
        // one hunts again); near the tip it serves us fully.
        fd = fb_fd; fb_fd = -1;
        snprintf(picked, sizeof picked, "%s", fb_picked);
        idx_sync_peer_height = fb_h; idx_sync_peer_services = (uint64_t)fb_svc;
        snprintf((char *)idx_sync_peer_agent, sizeof idx_sync_peer_agent, "%s", fb_agent);
        if (idx_sync_peer_height > 0) idx_db_set_peer_height(db, idx_sync_peer_height);
        fprintf(stderr, "  no archive peer reachable — using limited peer %s\n", picked);
    }
    if (fb_fd >= 0) close(fb_fd);
    if (fd < 0) { fprintf(stderr, "no peer reachable (%d candidates)\n", nc); idx_db_close(db); return 1; }
    fprintf(stderr, "connected %s, syncing from height %lld (activation %lld, peer height %lld, agent %s)\n",
            picked, (long long)(height + 1), (long long)activation,
            (long long)idx_sync_peer_height, (const char *)idx_sync_peer_agent);
    net_send(fd, coin->magic, "getaddr", NULL, 0);   // harvest the peer's addr view

    int idle = 0;
    char vwhy[128];
    while (idle < 3 && !idx_sync_stop) {
        // getblocks: standard exponential locator over our stored chain, terminated
        // by the profile checkpoint — after a reorg past our tip the peer then finds
        // the deepest common ancestor instead of falling back to genesis.
        uint8_t loc[34][32]; int nloc = 0;
        memcpy(loc[nloc++], tip, 32);
        { int64_t step = 1, h = height;
          while (nloc < 32 && h - step > coin->start) {
              h -= step;
              if (idx_db_block_get(db, h, loc[nloc])) nloc++;
              if (nloc >= 10) step *= 2;
          }
          if (height > coin->start) memcpy(loc[nloc++], coin->start_hash, 32); }
        uint8_t gb[4 + 3 + 34*32 + 32]; int o = 0;
        for (int i = 0; i < 4; i++) gb[o++] = (70015 >> (8*i)) & 0xff;
        put_varint(gb, &o, (uint64_t)nloc);
        for (int i = 0; i < nloc; i++) { memcpy(gb + o, loc[i], 32); o += 32; }
        memset(gb + o, 0, 32); o += 32;                              // hash_stop
        net_send(fd, coin->magic, "getblocks", gb, (uint32_t)o);

        int got_any = 0;
        // collect block hashes from inv, request + fold each
        char cmd[13]; uint8_t *pl; uint32_t pl_len;
        int r = net_recv(fd, coin->magic, cmd, &pl, &pl_len, 10000);
        if (r != 1) { if (r == -1) continue; idle++; continue; }
        if (!strcmp(cmd, "ping")) { net_send(fd, coin->magic, "pong", pl, pl_len); free(pl); continue; }
        if (!strcmp(cmd, "addr")) { addr_harvest(db, pl, pl_len, 0); free(pl); continue; }
        if (strcmp(cmd, "inv") != 0) { free(pl); continue; }
        // parse inv: varint count, then [type(4)+hash(32)] — request blocks (type 2).
        // Bounds-check the count varint against pl_len before every read (a peer
        // controls these bytes). inv counts are ≤50000 (MAX_INV_SZ) so 0xFD+2 is the
        // only wide form that legitimately occurs; reject 0xFE/0xFF rather than OOB-read.
        if (pl_len < 1) { free(pl); continue; }
        int po = 0; uint64_t cnt = pl[po++];
        if (cnt == 0xFD) { if (pl_len < 3) { free(pl); continue; } cnt = pl[po] | (pl[po+1] << 8); po += 2; }
        else if (cnt >= 0xFE) { free(pl); continue; }
        uint8_t getd[3 + 36 * 600]; int go = 0; uint8_t want[600][32]; int nwant = 0;   // 3 = max varint prefix for ≤600
        for (uint64_t i = 0; i < cnt && (po + 36) <= (int)pl_len && nwant < 600; i++) {
            uint32_t type = pl[po] | (pl[po+1]<<8) | (pl[po+2]<<16) | ((uint32_t)pl[po+3]<<24); po += 4;
            const uint8_t *h = pl + po; po += 32;
            if (type == 2) { memcpy(want[nwant], h, 32); nwant++; }
        }
        free(pl);
        if (nwant == 0) { idle++; continue; }
        // build one getdata for all
        go = 0; put_varint(getd, &go, (uint64_t)nwant);
        for (int i = 0; i < nwant; i++) { getd[go++]=2; getd[go++]=0; getd[go++]=0; getd[go++]=0; memcpy(getd + go, want[i], 32); go += 32; }
        net_send(fd, coin->magic, "getdata", getd, (uint32_t)go);
        // receive nwant blocks (interleaved control messages tolerated)
        int recvd = 0;
        while (recvd < nwant && !idx_sync_stop) {
            r = net_recv(fd, coin->magic, cmd, &pl, &pl_len, 15000); if (r != 1) { if (r == -1) continue; break; }
            if (!strcmp(cmd, "ping")) { net_send(fd, coin->magic, "pong", pl, pl_len); free(pl); continue; }
            if (!strcmp(cmd, "addr")) { addr_harvest(db, pl, pl_len, 0); free(pl); continue; }
            if (strcmp(cmd, "block") != 0) { free(pl); continue; }
            // Connect only a block that extends our tip (hashPrevBlock == tip) — the
            // peer's continue-inv pushes its TIP hash after a full 500-batch, and
            // fetching that would fold a ~tip-height block as height+1. A block whose
            // prev is one of our OLDER stored hashes is the peer's branch after a
            // reorg: roll back to that ancestor and connect. Anything else is dropped;
            // the next getblocks round re-anchors at our locator.
            if (pl_len < 80) { free(pl); recvd++; continue; }
            if (memcmp(pl + 4, tip, 32) != 0) {
                int64_t fork_h = idx_db_block_height_by_hash(db, pl + 4);
                if (fork_h < 0 || fork_h >= height) { free(pl); recvd++; continue; }
                // A block we ALREADY connected (peer tip echo after a full
                // batch, or a re-inv race on a fresh block) is not a reorg —
                // rolling back on it would refold the whole state for nothing.
                uint8_t bh[32], have[32];
                idx_sha256d(pl, 80, bh);
                if (idx_db_block_get(db, fork_h + 1, have) && !memcmp(bh, have, 32)) {
                    free(pl); recvd++; continue;
                }
                // validate BEFORE rolling back: a forged branch block must not
                // cost us a state refold, let alone the state itself
                if (!block_validate(db, coin, fork_h + 1, pl, pl_len, vwhy, sizeof vwhy)) {
                    fprintf(stderr, "invalid block for height %lld from %s: %s — abandoning peer\n",
                            (long long)(fork_h + 1), picked, vwhy);
                    free(pl);
                    goto invalid_peer;
                }
                // most-work gate: only reorg to a branch with strictly MORE
                // cumulative work than ours above the fork. A valid-but-lighter
                // fork (first-valid-peer-wins) must never rewrite the chain.
                { char rwhy[160] = "";
                  int ow = branch_outweighs(fd, coin, db, fork_h, pl + 4, height, rwhy, sizeof rwhy);
                  if (ow < 0) {
                      fprintf(stderr, "reorg branch from %s invalid: %s — abandoning peer\n", picked, rwhy);
                      free(pl); goto invalid_peer;
                  }
                  if (ow == 0) {
                      fprintf(stderr, "reorg declined: peer branch at %lld not heavier than our tip %lld%s%s\n",
                              (long long)fork_h, (long long)height, rwhy[0] ? " — " : "", rwhy);
                      free(pl); recvd++; continue;              // keep our chain
                  } }
                fprintf(stderr, "reorg: peer branch at height %lld outweighs our tip %lld — rolling back\n",
                        (long long)fork_h, (long long)height);
                if (!idx_sync_rollback(&s, db, oracle, activation, fork_h)) {
                    // state is not trustworthy past a failed replay — bail hard
                    fprintf(stderr, "rollback replay failed — aborting sync\n");
                    free(pl); close(fd); serve_store_close(fc.serve); oracle_free(oracle); sm_free(s); idx_db_close(db); return 1;
                }
                fc.s = s;
                serve_store_prune_above(fc.serve, fork_h);   // drop stale served headers/blocks
                height = fork_h;
                if (!idx_db_block_get(db, height, tip)) memcpy(tip, coin->start_hash, 32);
                idx_db_save_sync(db, height, tip);
            }
            if (!block_validate(db, coin, height + 1, pl, pl_len, vwhy, sizeof vwhy)) {
                fprintf(stderr, "invalid block for height %lld from %s: %s — abandoning peer\n",
                        (long long)(height + 1), picked, vwhy);
                free(pl);
                goto invalid_peer;
            }
            if (connect_block(&fc, height + 1, pl, pl_len)) {
                height++;
                int64_t hh; idx_db_load_sync(db, &hh, tip);   // refresh tip hash (hh == height)
                got_any = 1;
            }
            free(pl); recvd++;
        }
        idx_db_project(db, s);
        if (got_any) { idle = 0; fprintf(stderr, "  height %lld (%d txs folded)\n", (long long)height, fc.folded); }
        else idle++;
    }
    fprintf(stderr, "sync idle — caught up at height %lld\n", (long long)height);
    if (idx_sync_peer_height > 0 && height >= idx_sync_peer_height)
        s_parity = time(NULL);          // hard parity, measured on a live socket
    idx_db_project(db, s);
    print_digest(s);
    idx_db_peers_prune(db, (int64_t)time(NULL), IDX_PEER_TTL_SECS, IDX_PEER_CAP);
    close(fd); serve_store_close(fc.serve); oracle_free(oracle); sm_free(s); idx_db_close(db);
    return 0;

invalid_peer:
    // the peer served a provably invalid block: everything further from it is
    // suspect. Demote it (the ladder stops preferring it), persist what folded
    // before the poison, and end the pass — the next pass dials someone else.
    idx_db_peer_bad(db, picked);
    idx_db_project(db, s);
    close(fd); serve_store_close(fc.serve); oracle_free(oracle); sm_free(s); idx_db_close(db);
    return 1;
}

// ── serve: the inbound chain-wire presence (discovery slice 3, step 1) ────────
// A pepenet node is a first-class chain peer: it listens on the chain port,
// does the version handshake advertising our "/pepenet-" agent (so a crawler
// classifies it), answers getaddr from the peer table, harvests inbound addr,
// and ponds pings. This is what makes a node reachable + discoverable — it
// CLOSES the discovery loop (a crawl now finds a real dns-aware node). Chain
// data serving (NODE_NETWORK_LIMITED) and carrier gossip (dn* commands) bolt
// onto this same poll loop in later steps; for now services is advertised 0
// (honest: we serve no blocks yet — the agent string is the dns-aware marker).
#define SERVE_MAX_CONN 64
#define SERVE_MSG_MAX  (2 * 1024 * 1024)
// outbound slots we keep pointed at overlay (pepenet) peers drawn from the
// persisted dnet pool — the startup re-dial target. Well under SERVE_MAX_CONN so
// inbound + chain dial_peers keep ample room.
#define MESH_DIAL_SEATS 8
// one failure-backoff window for every outbound seat kind (mesh + chain): a
// failed dial stamps last_try and the addr sits out this long before any
// topup offers it again (Core's GetChance decay, flattened to one step)
#define DIAL_RETRY_S    600
// liveness: a conn that never handshakes is cut at SHAKE; an established conn
// quiet past PING gets pinged; silent past DEAD it's dropped (Core: 2 min ping
// interval / 20 min timeout — tightened for a desktop node whose Peers page
// shouldn't show ghosts for long). Without this a peer that vanishes without a
// FIN (NAT expiry, sleep, crash) holds its slot forever — and each of its
// reconnects stacks a fresh conn next to the ghost.
#define SERVE_SHAKE_S   60
#define SERVE_PING_S    120
#define SERVE_DEAD_S    600
// per-host inbound BUDGET. A healthy peer legitimately shows up as one
// persistent conn (its serve plane's mesh seat) PLUS a brief transient (its
// pass-based sync dial or a crawl probe — those share a thread, never both at
// once). Budget both, with one seat of margin for a second node behind the
// same NAT or a closing transient still draining. At 1 this refused the sync
// pass of the very host whose mesh conn was parked on us — and on a small net
// (client + seed) that host has no other peer, so its sync starved until the
// mesh conn dropped and the two planes flapped forever. Still strict enough
// that one looping host can't eat the table (64 slots, 3 per host).
#define SERVE_INBOUND_PER_HOST 3

typedef struct {
    int fd;
    uint8_t *buf; size_t len, cap;    // accumulated inbound bytes (frames span reads)
    int up, sent_ver;
    char peer[80];                    // remote ip:port (log + self-learn source)
    const uint8_t *magic;             // coin magic (the mesh send fn needs it)
    int  outbound;                    // dialed → keep the slot + redial
    char host[80]; uint16_t rport; time_t redial_at;
    char hip[46];                     // host's resolved numeric ip ("" till resolved).
                                      // THE seat identity: every dedup compares ips,
                                      // every dial connects to this. A hostname in
                                      // `host` (the configured seed) is only ever a
                                      // recipe for refreshing it — dns is a pre-step
                                      // of the dial, never a peer identity.
    time_t last_rx;                   // last byte received (liveness clock)
    time_t last_ping;                 // last ping we originated (idle probe)
    time_t last_pull;                 // last mesh getblocks we sent (tip pull)
    char agent[128];                  // peer subver ("/pepenet-" ⇒ a mesh peer)
    int64_t peer_h;                   // peer's claimed start_height at handshake (0 unknown)
    void *mesh_handle;                // embedder's per-peer handle (NULL till peer_up)
    int  dn_asked;                    // we sent this pepenet peer a dngetaddr already
    int  self_sent;                   // we announced our own addr on this conn already
    int  mesh_seat;                   // outbound slot seated by overlay discovery
                                      // (idx_db_peers_dnet) — released if not pepenet
    int  chain_seat;                  // outbound slot seated by addrman-style selection
                                      // (chain_topup) — released on dial failure so the
                                      // next tick tries a different candidate
} SConn;
// the mesh send fn handed to peer_up: emit a dn* command on this peer's conn
static void serve_mesh_send(void *peer, const char *cmd, const uint8_t *pay, size_t n) {
    SConn *sc = (SConn *)peer;
    if (sc->fd >= 0) net_send(sc->fd, sc->magic, cmd, pay, (uint32_t)n);
}
static void sconn_reset(SConn *c) {   // wipe transient state, keep outbound redial info
    free(c->buf);
    int ob = c->outbound, ms = c->mesh_seat, cs = c->chain_seat; char host[80], hip[46]; uint16_t rp = c->rport;
    memcpy(host, c->host, sizeof host); memcpy(hip, c->hip, sizeof hip);
    c->fd = -1; c->buf = NULL; c->len = c->cap = 0; c->up = c->sent_ver = 0;
    c->peer[0] = 0; c->agent[0] = 0; c->hip[0] = 0; c->peer_h = 0; c->mesh_handle = NULL; c->dn_asked = 0; c->mesh_seat = 0;
    c->self_sent = 0; c->chain_seat = 0; c->last_rx = 0; c->last_ping = 0; c->last_pull = 0;
    c->outbound = ob; if (ob) { c->mesh_seat = ms; c->chain_seat = cs; memcpy(c->host, host, sizeof c->host); memcpy(c->hip, hip, sizeof c->hip); c->rport = rp; c->redial_at = time(NULL) + 15; }
}
// close + notify the mesh (peer_down) if this was a live mesh peer
static void serve_drop(SConn *c, const IdxMeshHooks *mesh) {
    if (c->mesh_handle && mesh && mesh->peer_down) mesh->peer_down(mesh->ud, c->mesh_handle);
    if (c->fd >= 0) close(c->fd);
    sconn_reset(c);
}

// ── live status snapshots (indexer.h — an embedding host's Peers page) ───────
// Seqlock, not a mutex: one writer each (the serve loop / the crawl pass), so
// readers spin on the sequence instead of adding a pthread dependency to the
// headless CLI. Writer: seq++ (odd = mid-write), mutate, seq++ (even). Reader:
// copy, then retry if seq moved or was odd. Snapshots are tiny and 1 Hz.
static struct { volatile unsigned seq; int n; IdxServeConn c[SERVE_MAX_CONN]; } g_conns;
static struct { volatile unsigned seq; IdxCrawlStatus s; } g_crawl;

static void serve_snap(SConn *conns, int nconn, time_t now) {
    g_conns.seq++;
    int n = 0;
    for (int i = 0; i < nconn; i++) {
        SConn *c = &conns[i];
        if (c->fd < 0 && !c->outbound) continue;      // free slot
        IdxServeConn *o = &g_conns.c[n++];
        snprintf(o->peer, sizeof o->peer, "%s", c->peer);
        snprintf(o->host, sizeof o->host, "%s", c->host);
        o->rport = c->rport;
        snprintf(o->agent, sizeof o->agent, "%s", c->agent);
        o->connected = c->fd >= 0;
        o->up        = c->up;
        o->outbound  = c->outbound;
        o->mesh_seat = c->mesh_seat;
        o->mesh      = c->mesh_handle != NULL;
        o->peer_height = c->peer_h;
        o->redial_in = (c->fd < 0 && c->outbound && c->redial_at > now)
                     ? (int64_t)(c->redial_at - now) : 0;
    }
    g_conns.n = n;
    g_conns.seq++;
}

int idx_serve_conns(IdxServeConn *out, int max) {
    unsigned s1, s2;
    int n;
    do {
        s1 = g_conns.seq;
        n = g_conns.n;
        if (n > max) n = max;
        if (n > 0) memcpy(out, g_conns.c, (size_t)n * sizeof *out);
        s2 = g_conns.seq;
    } while (s1 != s2 || (s1 & 1));
    return n;
}

volatile int64_t idx_serve_stage_seq = 0;   // indexer.h — bumps per newly staged block

// 1 iff the serve plane OWNS a relationship with this dial target: a live conn
// whose remote ip matches, or an outbound seat (connected or parked) whose
// dial-target text matches. THE one-connection-per-peer rule (indexer.h):
// sync passes and tx broadcasts must never open a second socket to such a
// peer — everything they need from it rides the standing connection (stage
// push/pull, stage-side reorgs, mempool inv relay).
int idx_serve_peer_held(const char *target) {
    if (!target || !*target) return 0;
    IdxServeConn c[SERVE_MAX_CONN];
    int n = idx_serve_conns(c, SERVE_MAX_CONN);
    size_t tl = strlen(target);
    for (int i = 0; i < n; i++) {
        if (c[i].connected && !strncmp(c[i].peer, target, tl) && c[i].peer[tl] == ':')
            return 1;
        if (c[i].outbound && c[i].host[0] && !strcmp(c[i].host, target))
            return 1;
    }
    return 0;
}

// Highest chain height any live serve-plane peer claimed at its handshake
// (indexer.h). With the stage, the sync pass's "am I at the network's tip
// without opening a socket" measure.
int64_t idx_serve_best_height(void) {
    IdxServeConn c[SERVE_MAX_CONN];
    int n = idx_serve_conns(c, SERVE_MAX_CONN);
    int64_t best = 0;
    for (int i = 0; i < n; i++)
        if (c[i].connected && c[i].up && c[i].peer_height > best) best = c[i].peer_height;
    return best;
}

void idx_crawl_status(IdxCrawlStatus *out) {
    unsigned s1, s2;
    do {
        s1 = g_crawl.seq;
        *out = g_crawl.s;
        s2 = g_crawl.seq;
    } while (s1 != s2 || (s1 & 1));
}

// one addr entry: time(4) services(8) ip(16, v4-mapped) port(2 BE). IPv4 only.
static int addr_entry(uint8_t *out, uint32_t *o, uint32_t cap,
                      const char *addr, int64_t services, int64_t t) {
    unsigned a, b, cc, d, port;
    if (sscanf(addr, "%u.%u.%u.%u:%u", &a, &b, &cc, &d, &port) != 5) return 0;
    if (a > 255 || b > 255 || cc > 255 || d > 255 || port > 65535) return 0;
    if (*o + 30 > cap) return 0;
    out[(*o)++] = (uint8_t)t; out[(*o)++] = (uint8_t)(t >> 8);
    out[(*o)++] = (uint8_t)(t >> 16); out[(*o)++] = (uint8_t)(t >> 24);
    for (int i = 0; i < 8; i++) out[(*o)++] = (uint8_t)(services >> (8 * i));
    for (int i = 0; i < 10; i++) out[(*o)++] = 0;
    out[(*o)++] = 0xFF; out[(*o)++] = 0xFF;
    out[(*o)++] = (uint8_t)a; out[(*o)++] = (uint8_t)b;
    out[(*o)++] = (uint8_t)cc; out[(*o)++] = (uint8_t)d;
    out[(*o)++] = (uint8_t)(port >> 8); out[(*o)++] = (uint8_t)port;
    return 1;
}

static void serve_send_version(int fd, const Coin *coin, int64_t our_height, int64_t services) {
    uint8_t v[256]; int o = 0;
    for (int i = 0; i < 4; i++) v[o++] = (70015 >> (8*i)) & 0xff;
    for (int i = 0; i < 8; i++) v[o++] = (services >> (8*i)) & 0xff;
    int64_t now = (int64_t)time(NULL); for (int i = 0; i < 8; i++) v[o++] = (now >> (8*i)) & 0xff;
    memset(v + o, 0, 26); o += 26;                                   // addr_recv
    memset(v + o, 0, 26); o += 26;                                   // addr_from
    uint64_t sn = self_nonce(); for (int i = 0; i < 8; i++) v[o++] = (uint8_t)(sn >> (8*i));  // nonce (self-connect guard)
    size_t ual = strlen(idx_sync_agent); if (ual > 100) ual = 100;
    v[o++] = (uint8_t)ual; memcpy(v + o, idx_sync_agent, ual); o += (int)ual;
    for (int i = 0; i < 4; i++) v[o++] = (our_height >> (8*i)) & 0xff;
    v[o++] = 1;                                                      // relay: we accept tx invs (mempool)
    net_send(fd, coin->magic, "version", v, (uint32_t)o);
}

// Overlay peer discovery (peer-discovery follow-up #1): dngetaddr / dnaddr.
// The host chain's addr gossip is subver-blind — it advertises IPs, not "this
// node speaks pepenet" — so a pepenet node otherwise finds its own kind only by
// chain-crawl luck + a hardcoded seed. These two ride the SAME chain wire as
// native commands (like getaddr/addr) but carry ONLY pepenet-aware peers: on
// handshake each side asks the other for its pepenet peer list, and the answer
// re-seats the dialer. Find one → find all. Native to the indexer (not the
// carrier mesh) so a standalone `serve`/dnsd participates with mesh == NULL.
#define SERVE_DNADDR_MAX 256
static void serve_send_dnaddr(SConn *c, const Coin *coin, sqlite3 *db,
                              const char *self, uint16_t port) {
    char pool[SERVE_DNADDR_MAX][80];
    int n = idx_db_peers_dnet(db, pool, SERVE_DNADDR_MAX, 0);
    // advertise ourselves iff we listen and learned our external ip (a dial-only
    // node has neither, and correctly stays out of everyone's dnaddr)
    int adv_self = (port && self && *self) ? 1 : 0;
    int total = n + adv_self; if (total > SERVE_DNADDR_MAX) total = SERVE_DNADDR_MAX;
    uint8_t *out = malloc(3 + (size_t)SERVE_DNADDR_MAX * 30);
    if (!out) return;
    int vo = 0; put_varint(out, &vo, (uint64_t)total);
    uint32_t o = (uint32_t)vo; int put = 0;
    int64_t now = (int64_t)time(NULL);
    if (adv_self && put < total) put += addr_entry(out, &o, 3 + SERVE_DNADDR_MAX*30u, self, 1LL<<10, now);
    for (int i = 0; i < n && put < total; i++) {
        if (self && *self && !strcmp(pool[i], self)) continue;   // don't echo self twice
        put += addr_entry(out, &o, 3 + SERVE_DNADDR_MAX*30u, pool[i], 0, now);
    }
    net_send(c->fd, coin->magic, "dnaddr", out, o);
    free(out);
}

// Push our own addr (ONE entry) on this connection — Core's AdvertiseLocal.
// This is the only way a desktop node's address ever enters the host chain's
// addr gossip: core nodes never getaddr their INBOUND peers, so answering
// getaddr with self can't reach a node we dialed. Announce → the peer's
// addrman stores + relays it → another node's crawl harvests it → dials our
// chain port → reads the "/pepenet-" subver → the mesh finds itself. Gated
// on listening (port) + a learned external ip (version.addr_recv); actually
// REACHING the announced port is still the operator's port-forward.
static void serve_announce_self(const SConn *c, const Coin *coin,
                                const char *self, int64_t services) {
    uint8_t out[3 + 30];
    int vo = 0;
    put_varint(out, &vo, 1);
    uint32_t o = (uint32_t)vo;
    if (!addr_entry(out, &o, sizeof out, self, services, (int64_t)time(NULL))) return;
    net_send(c->fd, coin->magic, "addr", out, o);
    fprintf(stderr, "serve: announced self %s to %s\n", self, c->peer);
}

static void serve_dispatch(SConn *c, SConn *conns, const Coin *coin, sqlite3 *db, ServeStore *ss,
                           int64_t services, const char *cmd, uint8_t *pl, uint32_t pln,
                           char self[80], uint16_t port, const IdxMeshHooks *mesh) {
    if (!strcmp(cmd, "version")) {
        // learn our own address from their addr_recv (the ip THEY dialed) —
        // paired with our listen port, this is what we advertise as self
        if (!*self && pln >= 46 && pl[38] == 0xFF && pl[39] == 0xFF) {
            unsigned a = pl[40];
            if (a && a != 127 && a != 10)
                snprintf(self, 80, "%u.%u.%u.%u:%u", pl[40], pl[41], pl[42], pl[43], port);
        }
        // capture the peer's subver (agent) — "/pepenet-" marks a mesh peer —
        // and its claimed start_height (the varstr's tail), the serve plane's
        // own network-tip signal (idx_serve_best_height)
        { uint64_t off = 4+8+8+26+26+8, ua;
          if (pln > off) { ua = pl[off++];
              if (ua == 0xFD && pln >= off + 2) { ua = pl[off] | (pl[off+1] << 8); off += 2; }
              if (ua <= 100 && pln >= off + ua) { memcpy(c->agent, pl + off, ua); c->agent[ua] = 0; }
              if (ua <= 100 && pln >= off + ua + 4) {
                  uint64_t ho = off + ua;
                  c->peer_h = (int64_t)((uint32_t)pl[ho] | ((uint32_t)pl[ho+1] << 8) |
                                        ((uint32_t)pl[ho+2] << 16) | ((uint32_t)pl[ho+3] << 24));
              } } }
        if (!c->sent_ver) {
            int64_t h = 0; uint8_t tip[32]; idx_db_load_sync(db, &h, tip);
            serve_send_version(c->fd, coin, h, services);
            c->sent_ver = 1;
        }
        net_send(c->fd, coin->magic, "verack", NULL, 0);
        c->up = 1;
        // a marked peer + a mesh embedder → hand it up so the carrier gossips
        if (mesh && mesh->peer_up && !c->mesh_handle && AGENT_MARKED(c->agent))
            c->mesh_handle = mesh->peer_up(mesh->ud, c, serve_mesh_send);
        // overlay discovery (mesh-independent): solicit this marked peer's
        // overlay peer list, once per connection
        if (!c->dn_asked && AGENT_MARKED(c->agent)) {
            net_send(c->fd, coin->magic, "dngetaddr", NULL, 0);
            c->dn_asked = 1;
        }
        // self-announcement (see serve_announce_self) — once per connection
        if (port && *self && !c->self_sent) {
            serve_announce_self(c, coin, self, services);
            c->self_sent = 1;
        }
    } else if (!strcmp(cmd, "verack")) {
        c->up = 1;
    } else if (!strcmp(cmd, "dngetaddr")) {
        serve_send_dnaddr(c, coin, db, self, port);          // answer with our pepenet peers
    } else if (!strcmp(cmd, "dnaddr")) {
        addr_harvest(db, pl, pln, 1);                        // vouched pepenet peers → dnet pool
    } else if (!strncmp(cmd, "dn", 2) && cmd[2] && mesh && mesh->peer_msg && c->mesh_handle) {
        mesh->peer_msg(mesh->ud, c->mesh_handle, cmd + 2, pl, (int)pln);   // carrier dn* command
    } else if (!strcmp(cmd, "ping")) {
        net_send(c->fd, coin->magic, "pong", pl, pln);
    } else if (!strcmp(cmd, "getaddr")) {
        IdxPeerRow *rows = malloc(sizeof(IdxPeerRow) * 1000);
        if (!rows) return;
        int n = idx_db_peers_rows(db, rows, 1000);
        uint8_t *out = malloc(3 + 1001u * 30);
        if (!out) { free(rows); return; }
        int total = n + (*self ? 1 : 0); if (total > 1000) total = 1000;
        int vo = 0; put_varint(out, &vo, (uint64_t)total);
        uint32_t o = (uint32_t)vo;
        int64_t now = (int64_t)time(NULL); int put = 0;
        if (*self && put < total) put += addr_entry(out, &o, 3 + 1001u*30, self, 0, now);
        for (int i = 0; i < n && put < total; i++)
            put += addr_entry(out, &o, 3 + 1001u*30, rows[i].addr, rows[i].services, rows[i].last_seen);
        net_send(c->fd, coin->magic, "addr", out, o);
        free(out); free(rows);
    } else if (!strcmp(cmd, "addr")) {
        addr_harvest(db, pl, pln, 0);
    } else if (!strcmp(cmd, "getheaders") && ss) {
        // version(4) + varint nloc + nloc*32 locator (newest→oldest) + hash_stop(32)
        if (pln < 5) return;
        uint32_t o = 4; uint64_t nloc = pl[o++];
        if (nloc == 0xFD) { if (pln < o + 2) return; nloc = pl[o] | (pl[o+1] << 8); o += 2; }
        else if (nloc >= 0xFE) return;
        if (nloc > 2000 || o + nloc * 32 + 32 > pln) return;
        int64_t start = serve_store_locate(ss, pl + o, (int)nloc);   // -1 → from earliest
        uint8_t *out = malloc(3 + 2000u * 81);
        if (!out) return;
        uint8_t hbuf[2000 * 80]; int nh = 0;
        serve_store_headers_from(ss, start, hbuf, sizeof hbuf, 2000, &nh);
        int vo = 0; put_varint(out, &vo, (uint64_t)nh);
        uint32_t oo = (uint32_t)vo;
        for (int i = 0; i < nh; i++) { memcpy(out + oo, hbuf + i * 80, 80); oo += 80; out[oo++] = 0x00; }  // 0 tx count
        if (nh) net_send(c->fd, coin->magic, "headers", out, oo);
        free(out);
    } else if (!strcmp(cmd, "getblocks") && ss) {
        // the sync path's forward walk (getblocks → inv → getdata → block) —
        // what a peer's per-pass sync actually speaks at us. Answer with the
        // block hashes above its deepest locator match, but ONLY while the raw
        // blocks are still inside our window: a limited node must serve the
        // whole run or stay silent, because a gapped inv would feed the
        // requester blocks its sequential fold can't connect (it would read as
        // an invalid peer and abandon us). Silence = "can't help / caught up",
        // exactly what the requester's ladder expects — it gates deep sync on
        // NODE_NETWORK and only leans on us near the tip.
        if (pln < 5) return;
        uint32_t o = 4; uint64_t nloc = pl[o++];
        if (nloc == 0xFD) { if (pln < o + 2) return; nloc = pl[o] | (pl[o+1] << 8); o += 2; }
        else if (nloc >= 0xFE) return;
        if (nloc > 2000 || o + nloc * 32 + 32 > pln) return;
        int64_t start = serve_store_locate(ss, pl + o, (int)nloc);   // -1 = no common block: stay silent
        int64_t wfloor = serve_store_win_floor(ss);
        if (start < 0 || wfloor < 0 || start + 1 < wfloor) return;
        uint8_t (*hs)[32] = malloc(500 * 32);
        if (!hs) return;
        int nh = serve_store_hashes_from(ss, start, hs, 500);
        if (nh > 0) {
            uint8_t *out = malloc(3 + 500u * 36);
            if (out) {
                int vo = 0; put_varint(out, &vo, (uint64_t)nh);
                uint32_t oo = (uint32_t)vo;
                for (int i = 0; i < nh; i++) {
                    out[oo++] = 2; out[oo++] = 0; out[oo++] = 0; out[oo++] = 0;   // MSG_BLOCK
                    memcpy(out + oo, hs[i], 32); oo += 32;
                }
                net_send(c->fd, coin->magic, "inv", out, oo);
                free(out);
            }
        }
        free(hs);
    } else if (!strcmp(cmd, "getdata")) {
        if (pln < 1) return;
        uint32_t o = 0; uint64_t cnt = pl[o++];
        if (cnt == 0xFD) { if (pln < 3) return; cnt = pl[o] | (pl[o+1] << 8); o += 2; }
        else if (cnt >= 0xFE) return;
        for (uint64_t i = 0; i < cnt && o + 36 <= pln; i++, o += 36) {
            uint32_t type = pl[o] | (pl[o+1]<<8) | (pl[o+2]<<16) | ((uint32_t)pl[o+3]<<24);
            if (type == 2 && ss) {                         // block (type 2) — from the serve store
                uint8_t *raw; size_t rl;
                if (serve_store_block(ss, pl + o + 4, &raw, &rl)) {
                    net_send(c->fd, coin->magic, "block", raw, (uint32_t)rl);
                    free(raw);
                }
            } else if (type == 1) {                        // tx (type 1) — from the mempool
                size_t rl; uint8_t *raw = mempool_get_copy(pl + o + 4, &rl);
                if (raw) { net_send(c->fd, coin->magic, "tx", raw, (uint32_t)rl); free(raw); }
            }
        }
    } else if (!strcmp(cmd, "inv")) {
        // a peer advertises inventory. Tx invs (type 1) we don't have → pull
        // for the mempool. Block invs (type 2) we don't know → pull into the
        // blockstage for the sync pass (sync-over-one-connection): the fold
        // stays on the sync side, this thread only ferries bytes off the
        // mesh line so no second socket is ever needed to follow the tip.
        if (pln < 1) return;
        uint32_t o = 0; uint64_t cnt = pl[o++];
        if (cnt == 0xFD) { if (pln < 3) return; cnt = pl[o] | (pl[o+1] << 8); o += 2; }
        else if (cnt >= 0xFE) return;
        uint8_t want[128][32]; int nreq = 0;
        uint8_t wblk[16][32]; int nblk = 0;
        for (uint64_t i = 0; i < cnt && o + 36 <= pln; i++, o += 36) {
            uint32_t type = pl[o] | (pl[o+1]<<8) | (pl[o+2]<<16) | ((uint32_t)pl[o+3]<<24);
            const uint8_t *h = pl + o + 4;
            if (type == 1 && nreq < 128) {
                if (mempool_has(h) || mempool_seen(h)) continue;
                memcpy(want[nreq++], h, 32);
            } else if (type == 2 && nblk < 16 && ss && c->up) {
                if (serve_store_have(ss, h)) continue;         // headers or stage: known
                memcpy(wblk[nblk++], h, 32);
            }
        }
        if (nreq + nblk) {
            uint8_t getd[3 + 36 * (128 + 16)]; int go = 0; put_varint(getd, &go, (uint64_t)(nreq + nblk));
            for (int i = 0; i < nreq; i++) { getd[go++]=1; getd[go++]=0; getd[go++]=0; getd[go++]=0; memcpy(getd + go, want[i], 32); go += 32; }
            for (int i = 0; i < nblk; i++) { getd[go++]=2; getd[go++]=0; getd[go++]=0; getd[go++]=0; memcpy(getd + go, wblk[i], 32); go += 32; }
            net_send(c->fd, coin->magic, "getdata", getd, (uint32_t)go);
        }
    } else if (!strcmp(cmd, "block")) {
        // a block body off a serve conn (answer to the inv-pull above, or an
        // unsolicited push): park it in the stage. Validation, folding and
        // reorg judgment all stay on the sync side — this thread never even
        // parses past the header. stage_put caps + ages the table, so junk
        // from a hostile peer costs bounded disk and zero state.
        if (!ss || pln < 80) return;
        uint8_t bh[32]; idx_sha256d(pl, 80, bh);
        if (serve_store_stage_put(ss, bh, pl + 4, pl, pln, (int64_t)time(NULL)))
            idx_serve_stage_seq++;               // embedding hosts: fold-on-inv nudge
    } else if (!strcmp(cmd, "tx")) {
        // validate + pool + relay. On accept, announce (inv type 1) to every other
        // live peer — the receiver's own has/seen guard breaks the echo loop.
        uint8_t txid[32]; char why[128];
        if (mempool_accept(pl, pln, txid, why, sizeof why)) {
            uint8_t inv[3 + 36]; int io = 0; put_varint(inv, &io, 1);
            inv[io++]=1; inv[io++]=0; inv[io++]=0; inv[io++]=0; memcpy(inv + io, txid, 32); io += 32;
            for (int i = 0; i < SERVE_MAX_CONN; i++) {
                SConn *o = &conns[i];
                if (o->fd >= 0 && o->up && o != c) net_send(o->fd, o->magic ? o->magic : coin->magic, "inv", inv, (uint32_t)io);
            }
        }
    } else if (!strcmp(cmd, "mempool")) {
        // answer with an inv of our whole pool (BIP35). Bounded to one message.
        uint8_t (*ids)[32] = malloc(sizeof *ids * 1000);
        if (!ids) return;
        size_t n = mempool_txids(ids, 1000);
        if (n) {
            uint8_t *inv = malloc(3 + n * 36);
            if (inv) { int io = 0; put_varint(inv, &io, (uint64_t)n);
                for (size_t i = 0; i < n; i++) { inv[io++]=1; inv[io++]=0; inv[io++]=0; inv[io++]=0; memcpy(inv + io, ids[i], 32); io += 32; }
                net_send(c->fd, coin->magic, "inv", inv, (uint32_t)io); free(inv); }
        }
        free(ids);
    }
    // dn* carrier commands: step 3
}

// Dial `host:port`, do the version handshake (WE speak first), capture the
// peer's agent. Fills `self` (when empty and we listen on `lport`) from the
// peer's version.addr_recv — the ip THEY see us as. Outbound is the only
// handshake a NAT'd node ever completes, so without this a node nobody dials
// never learns the address it should announce (self stayed "" forever).
// Returns the connected fd (blocking), or -1.
static int serve_dial(const char *host, uint16_t port, const Coin *coin,
                      int64_t services, int64_t our_h, char agent_out[128],
                      int64_t *services_out, char self[80], uint16_t lport,
                      int64_t *height_out) {
    int fd = net_connect(host, port);
    if (fd < 0) return -1;
    serve_send_version(fd, coin, our_h, services);
    agent_out[0] = 0; if (services_out) *services_out = 0; if (height_out) *height_out = 0;
    int gv = 0, gvk = 0, is_self = 0;
    for (int i = 0; i < 12 && !(gv && gvk) && !is_self; i++) {
        char cmd[13]; uint8_t *pl; uint32_t pn;
        int r = net_recv(fd, coin->magic, cmd, &pl, &pn, 8000);
        if (r != 1) { if (r == -1) continue; close(fd); return -1; }
        if (!strcmp(cmd, "version")) {
            gv = 1;
            uint64_t vn;                                             // did we dial ourselves?
            if (ver_nonce(pl, pn, &vn) && vn == self_nonce()) is_self = 1;
            if (pn >= 12 && services_out) { uint64_t sv = 0; for (int b = 0; b < 8; b++) sv |= (uint64_t)pl[4+b] << (8*b); *services_out = (int64_t)sv; }
            if (self && lport && !*self && pn >= 46 && pl[38] == 0xFF && pl[39] == 0xFF) {
                unsigned a = pl[40];
                if (a && a != 127 && a != 10)
                    snprintf(self, 80, "%u.%u.%u.%u:%u", pl[40], pl[41], pl[42], pl[43], lport);
            }
            uint64_t off = 4+8+8+26+26+8, ua;
            if (pn > off) { ua = pl[off++];
                if (ua == 0xFD && pn >= off + 2) { ua = pl[off] | (pl[off+1] << 8); off += 2; }
                if (ua <= 100 && pn >= off + ua) { memcpy(agent_out, pl + off, ua); agent_out[ua] = 0; }
                if (ua <= 100 && height_out && pn >= off + ua + 4) {   // claimed start_height (tail)
                    uint64_t ho = off + ua;
                    *height_out = (int64_t)((uint32_t)pl[ho] | ((uint32_t)pl[ho+1] << 8) |
                                            ((uint32_t)pl[ho+2] << 16) | ((uint32_t)pl[ho+3] << 24));
                } }
            net_send(fd, coin->magic, "verack", NULL, 0);
        } else if (!strcmp(cmd, "verack")) gvk = 1;
        else if (!strcmp(cmd, "ping")) net_send(fd, coin->magic, "pong", pl, pn);
        free(pl);
    }
    if (is_self) { close(fd); return -2; }    // dialed ourselves — tell the caller to drop this peer
    if (gv && gvk) return fd;
    close(fd); return -1;
}

// is any slot (other than `except`) already pointed at this machine? Live
// sockets compare by peer ip — the port always differs across directions (an
// inbound conn arrives from an ephemeral port, the pool row names the listen
// port), so an ip:port equality check can never see that they're the same
// machine. Disconnected seats compare by their resolved identity (hip) first,
// then the raw host text — so the configured seed's numeric addr row and the
// hostname seat read as ONE peer once either has resolved.
// One connection per machine is Core's rule too (ConnectNode → FindNode by
// CNetAddr): if a peer is connected — EITHER direction — we don't also dial
// it. That's what keeps an outbound-only (NAT'd) peer that dialed us in from
// being redialed forever off its own dnaddr self-announce.
static int conn_host_live(SConn *conns, const SConn *except, const char *host) {
    for (int i = 0; i < SERVE_MAX_CONN; i++) {
        SConn *c = &conns[i];
        if (c == except) continue;
        if (c->fd >= 0 && c->peer[0]) {
            char ip[80]; snprintf(ip, sizeof ip, "%s", c->peer);
            char *col = strrchr(ip, ':'); if (col) *col = 0;
            if (!strcmp(ip, host)) return 1;
        }
        if (c->fd < 0 && c->outbound &&
            ((c->hip[0]  && !strcmp(c->hip,  host)) ||
             (c->host[0] && !strcmp(c->host, host)))) return 1;
    }
    return 0;
}
// point an outbound seat at a dial target. A numeric target is its own dial
// identity immediately; a hostname target starts unresolved (hip "") and the
// dial loop resolves it per attempt.
static void seat_point(SConn *c, const char *host, uint16_t rp) {
    snprintf(c->host, sizeof c->host, "%s", host);
    c->rport = rp; c->redial_at = 0; c->hip[0] = 0;
    unsigned char a4[4]; struct in6_addr a6;
    if (inet_pton(AF_INET, host, a4) == 1 || inet_pton(AF_INET6, host, &a6) == 1)
        snprintf(c->hip, sizeof c->hip, "%s", host);
}
// Keep up to `target` outbound slots pointed at overlay peers from the persisted
// dnet pool. This is BOTH the startup re-dial (a returning node re-embeds into
// the mesh from its own memory) and the live reaction to freshly-gossiped
// dnaddr peers. Idempotent: seats only addrs not already connected/seated, only
// into free (fd<0, non-outbound) slots. Newly seated slots dial on the next tick.
static void mesh_seat_topup(SConn *conns, sqlite3 *db, const Coin *coin, int target,
                            const char *self) {
    int seated = 0;
    for (int i = 0; i < SERVE_MAX_CONN; i++) if (conns[i].mesh_seat) seated++;
    if (seated >= target) return;
    // pool query excludes rows in failure backoff — a mesh addr whose dial just
    // failed (e.g. an outbound-only peer announcing a port it can't serve) sits
    // out DIAL_RETRY_S instead of being re-seated on the very next tick
    char pool[64][80];
    int n = idx_db_peers_dnet(db, pool, 64, (int64_t)time(NULL) - DIAL_RETRY_S);
    for (int i = 0; i < n && seated < target; i++) {
        int slot = -1;
        for (int s = 0; s < SERVE_MAX_CONN; s++)
            if (conns[s].fd < 0 && !conns[s].outbound) { slot = s; break; }
        if (slot < 0) break;                              // no room — inbound has priority
        char host[80]; uint16_t rp; peer_split(pool[i], host, sizeof host, &rp, coin->port);
        // one connection per host, either direction: a peer already connected
        // (a NAT'd node that dialed US in) or already seated is never dialed again
        if (conn_host_live(conns, NULL, host)) continue;
        // never seat ourselves. addr_harvest keeps our addr out of the pool going
        // forward, but rows persisted before we learned our ip (or by an older
        // build) live until the TTL prune — without this they get re-seated every
        // tick, and the dial loop's drop leaves the seat free for the same row.
        if (host_is_self(host, self)) continue;
        memset(&conns[slot], 0, sizeof conns[slot]);
        conns[slot].fd = -1; conns[slot].outbound = 1; conns[slot].mesh_seat = 1;
        seat_point(&conns[slot], host, rp);
        seated++;
    }
}

// Dogecoin-Core-style outbound maintenance (addrman-lite): keep up to
// CHAIN_DIAL_TARGET outbound chain connections beyond the mesh seats.
// Selection mirrors AddrMan::Select at desk scale: alternate proven ("tried",
// last_good>0, freshest-proven first) and unproven ("new", harvested
// NODE_NETWORK addrs, random order) — Core's ~50/50 — then filter: failure
// backoff (an addr whose last try didn't land a handshake sits out
// DIAL_RETRY_S), one outbound per /16 netgroup (Core's eclipse defense),
// never a host already connected or seated, never ourselves (we self-announce,
// so our own addr comes back in the harvest). ONE candidate seated per tick:
// dials are blocking on this thread, so a swamp of dead addrs must not stall
// the loop — a failed dial stamps last_try and frees the seat.
#define CHAIN_DIAL_TARGET 8
// IPv4 /16 netgroup equality on "a.b.c.d[:port]" text (Core buckets by /16;
// a hostname never matches an ip, which is the right miss).
static int same_group16(const char *a, const char *b) {
    int dots = 0;
    for (size_t i = 0; a[i] && b[i]; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '.' && ++dots == 2) return 1;
    }
    return 0;
}
static void chain_topup(SConn *conns, sqlite3 *db, const Coin *coin, const char *self) {
    int have = 0, slot = -1;
    for (int i = 0; i < SERVE_MAX_CONN; i++) {
        SConn *c = &conns[i];
        if (c->outbound && !c->mesh_seat) have++;
        else if (slot < 0 && c->fd < 0 && !c->outbound) slot = i;
    }
    if (have >= CHAIN_DIAL_TARGET || slot < 0) return;
    static int flip = 0;                   // tried/new alternation (Core's ~50/50)
    int start = flip++ & 1;                // 0 → lead with tried; other class as fallback
    int64_t now = (int64_t)time(NULL);
    IdxPeerSel cand[32];
    for (int half = 0; half < 2; half++) {
        int n = idx_db_peers_select(db, cand, 32, ((start + half) & 1) == 0);
        for (int i = 0; i < n; i++) {
            IdxPeerSel *p = &cand[i];
            if (p->last_try > p->last_good && now - p->last_try < DIAL_RETRY_S) continue;
            char host[80]; uint16_t rp; peer_split(p->addr, host, sizeof host, &rp, coin->port);
            if (conn_host_live(conns, NULL, host)) continue;
            if (host_is_self(host, self)) continue;
            int clash = 0;
            for (int k = 0; k < SERVE_MAX_CONN && !clash; k++)
                if (conns[k].outbound && conns[k].host[0] && same_group16(conns[k].host, host)) clash = 1;
            if (clash) continue;
            memset(&conns[slot], 0, sizeof conns[slot]);
            conns[slot].fd = -1; conns[slot].outbound = 1; conns[slot].chain_seat = 1;
            seat_point(&conns[slot], host, rp);
            return;
        }
    }
}

// The chain-wire presence (indexer.h). port 0 = dial-only. `dial_peers` =
// comma host:port list kept connected. `mesh` non-NULL carries carrier gossip
// as dn* commands on pepenet peers.
int idx_serve(const char *coinname, const char *dbpath, uint16_t port,
              const char *dial_peers, volatile int *stop, const IdxMeshHooks *mesh) {
    const Coin *coin = coin_by_name(coinname); if (!coin) return -1;
    (void)self_nonce();                      // generate the version nonce now (before threads race)
    sqlite3 *db = idx_db_open(dbpath); if (!db) return -1;
    idx_db_peers_scrub(db);                  // drop pre-fix hostname addr rows
    int lfd = -1;
    if (port) {
        lfd = socket(AF_INET, SOCK_STREAM, 0);
        if (lfd < 0) { idx_db_close(db); return -1; }
        int yes = 1; setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
        struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET; sa.sin_addr.s_addr = INADDR_ANY; sa.sin_port = htons(port);
        if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(lfd, 16) != 0) {
            // The port is already taken — almost always a full node (Pepecoin
            // Core) bound to the chain port on the same box. That must NOT kill
            // the serve plane: this thread also carries the DNS mesh gossip and
            // the publish drain, and returning here left the node unable to
            // issue or sync DNS records at all. Degrade to dial-only (what a
            // NAT'd node does anyway): we lose inbound crawl-discoverability —
            // which needs a forwarded, unshared port regardless — but keep the
            // outbound mesh, block staging, and publish drain fully alive.
            // (strerror(errno) reads "No error" on Windows: Winsock reports the
            // in-use bind via WSAGetLastError, not errno — so name the cause.)
            fprintf(stderr, "serve: port %u already in use (a full node on this "
                    "host?) — running dial-only, no inbound\n", port);
            close(lfd); lfd = -1;
        }
    }
    char serve_path[600];
    { const char *slash = strrchr(dbpath, '/');
      if (slash) snprintf(serve_path, sizeof serve_path, "%.*s/serve-%s.db",
                          (int)(slash - dbpath), dbpath, coinname);
      else snprintf(serve_path, sizeof serve_path, "serve-%s.db", coinname); }
    ServeStore *ss = serve_store_open(serve_path);
    int64_t services = (ss && serve_store_tip(ss) >= 0) ? (1LL << 10) : 0;
    int64_t our_h = 0; { uint8_t tip[32]; idx_db_load_sync(db, &our_h, tip); }
    if (port) fprintf(stderr, "serve: listening on 0.0.0.0:%u (agent %s, services 0x%llx)\n",
                      port, idx_sync_agent, (unsigned long long)services);
    else fprintf(stderr, "serve: dial-only (agent %s, services 0x%llx)\n",
                 idx_sync_agent, (unsigned long long)services);

    SConn conns[SERVE_MAX_CONN];
    for (int i = 0; i < SERVE_MAX_CONN; i++) { memset(&conns[i], 0, sizeof conns[i]); conns[i].fd = -1; }
    // our own advertised addr ("ip:port"), learned from the first peer that tells
    // us — declared up here because the startup mesh re-seat below already needs
    // it to keep our own row out of the seats
    char self[80] = "";
    // pre-seat outbound peers (dial on the first tick)
    if (dial_peers && *dial_peers) {
        char list[512]; snprintf(list, sizeof list, "%s", dial_peers);
        int slot = 0;
        for (char *sv, *t = strtok_r(list, ",", &sv); t && slot < SERVE_MAX_CONN; t = strtok_r(NULL, ",", &sv)) {
            char host[80]; uint16_t rp;
            peer_split(t, host, sizeof host, &rp, coin->port);
            conns[slot].outbound = 1; seat_point(&conns[slot], host, rp); slot++;
        }
    }
    // startup re-dial: seat the pepenet peers we remember from prior runs so the
    // node re-embeds into the mesh immediately instead of by chain-crawl luck
    mesh_seat_topup(conns, db, coin, MESH_DIAL_SEATS, self);
    // hold the first outbound dial a few seconds: lets the sync thread reach a real
    // peer and learn our external ip (g_self_ip) first, so if the seed points back
    // at us the dial loop skips it up front instead of blocking on a self-connect.
    time_t next_dial = time(NULL) + 5, next_prune = time(NULL) + 3600, next_snap = 0;
    time_t next_announce = 0;
    int64_t announced_tip = serve_store_tip(ss);   // boot: only NEW blocks get announced
    while (!(stop && *stop)) {
        time_t now = time(NULL);
        // republish the connection snapshot (embedding hosts' Peers page)
        if (now >= next_snap) { next_snap = now + 1; serve_snap(conns, SERVE_MAX_CONN, now); }
        // announce new tip blocks (inv) to every up conn. This is the push half
        // of sync-over-one-connection: the receiver's serve thread getdatas the
        // inv into its stage and its sync pass folds from there — a peer at tip
        // follows the chain on its ONE mesh conn, no transient sync socket.
        // Big jumps (our own catch-up) are not blasted — a peer that far behind
        // uses the socket ladder anyway; the mark just snaps forward.
        if (ss && now >= next_announce) {
            next_announce = now + 2;
            // the PULL half of sync-over-one-connection: ask each marked peer
            // for anything above our chain (getblocks on the standing conn).
            // The locator is a real exponential walk over our stored headers,
            // so after a reorg the peer finds the true fork point instead of
            // missing our stale tip and staying silent. Answers ride the same
            // inv → stage → fold path as the push — a missed inv heals HERE,
            // never on a transient socket. Cadence: 60 s at parity (one tiny
            // frame a minute), 5 s while the peer's claimed height says we're
            // behind (stage-cap-sized batches per round → fast catch-up).
            // Core chain seats stay push-only: deep gaps are the socket
            // ladder's job, against peers we hold no connection to.
            { int64_t pt = serve_store_tip(ss);
              if (pt >= 0) {
                  uint8_t loc[16][32]; int nloc = 0;
                  int64_t lh = pt, step = 1;
                  while (nloc < 16 && lh >= 0 && serve_store_hash_at(ss, lh, loc[nloc])) {
                      nloc++;
                      if (nloc >= 4) step *= 2;
                      lh -= step;
                  }
                  if (nloc > 0) {
                      uint8_t gb[4 + 3 + 16 * 32 + 32]; int go = 0;
                      for (int b = 0; b < 4; b++) gb[go++] = (70015 >> (8*b)) & 0xff;
                      put_varint(gb, &go, (uint64_t)nloc);
                      for (int i = 0; i < nloc; i++) { memcpy(gb + go, loc[i], 32); go += 32; }
                      memset(gb + go, 0, 32); go += 32;             // hash_stop
                      for (int i = 0; i < SERVE_MAX_CONN; i++) {
                          SConn *pc = &conns[i];
                          if (pc->fd < 0 || !pc->up || !AGENT_MARKED(pc->agent)) continue;
                          time_t cad = (pc->peer_h > pt + 2) ? 5 : 60;
                          if (now - pc->last_pull < cad) continue;
                          net_send(pc->fd, coin->magic, "getblocks", gb, (uint32_t)go);
                          pc->last_pull = now;
                      }
                  }
              } }
            int64_t st = serve_store_tip(ss);
            if (st < announced_tip) announced_tip = st;          // reorg pruned below the mark
            if (st > announced_tip) {
                if (st - announced_tip <= 32) {
                    uint8_t hs[32][32];
                    int nh = serve_store_hashes_from(ss, announced_tip, hs, 32);
                    if (nh > 0) {
                        uint8_t out[3 + 32 * 36]; int vo = 0;
                        put_varint(out, &vo, (uint64_t)nh);
                        uint32_t oo = (uint32_t)vo;
                        for (int i = 0; i < nh; i++) {
                            out[oo++] = 2; out[oo++] = 0; out[oo++] = 0; out[oo++] = 0;   // MSG_BLOCK
                            memcpy(out + oo, hs[i], 32); oo += 32;
                        }
                        for (int i = 0; i < SERVE_MAX_CONN; i++)
                            if (conns[i].fd >= 0 && conns[i].up)
                                net_send(conns[i].fd, coin->magic, "inv", out, oo);
                    }
                }
                announced_tip = st;
            }
        }
        // bound the peers table (addr harvest grows it every getaddr)
        if (now >= next_prune) {
            next_prune = now + 3600;
            idx_db_peers_prune(db, (int64_t)now, IDX_PEER_TTL_SECS, IDX_PEER_CAP);
            mempool_sweep((int64_t)now);          // drop txs unconfirmed past the expiry
        }
        // liveness: cut conns that never handshake; ping quiet peers; drop the
        // silent. A peer that vanished without a FIN otherwise holds its slot
        // forever, and its reconnects stack fresh conns next to the ghost.
        for (int i = 0; i < SERVE_MAX_CONN; i++) {
            SConn *c = &conns[i];
            if (c->fd < 0) continue;
            long idle = (long)(now - c->last_rx);
            if (!c->up) {
                if (idle > SERVE_SHAKE_S) {
                    fprintf(stderr, "serve: %s stalled in handshake %lds — dropping\n",
                            c->peer[0] ? c->peer : "(inbound)", idle);
                    serve_drop(c, mesh);
                }
            } else if (idle > SERVE_DEAD_S) {
                fprintf(stderr, "serve: %s silent %lds — dropping dead conn\n", c->peer, idle);
                serve_drop(c, mesh);
            } else if (idle > SERVE_PING_S && now - c->last_ping > SERVE_PING_S) {
                uint8_t pn[8]; uint64_t nn = (uint64_t)now ^ ((uint64_t)i << 48);
                for (int b = 0; b < 8; b++) pn[b] = (uint8_t)(nn >> (8 * b));
                net_send(c->fd, coin->magic, "ping", pn, 8);
                c->last_ping = now;      // any reply (pong or otherwise) feeds last_rx
            }
        }
        // maintain outbound connections
        if (now >= next_dial) {
            next_dial = now + 5;
            // pick up pepenet peers learned via dnaddr since the last tick
            mesh_seat_topup(conns, db, coin, MESH_DIAL_SEATS, self);
            // and keep ~8 outbound chain peers seated addrman-style
            chain_topup(conns, db, coin, self);
            for (int i = 0; i < SERVE_MAX_CONN; i++) {
                SConn *c = &conns[i];
                if (!c->outbound || c->fd >= 0 || now < c->redial_at) continue;
                // ONE CONNECTION PER PEER, either direction — and while it lives,
                // this seat just PARKS: no dial, no backoff clock, no churn. Pool
                // seats free instead (their pool holds other candidates); a
                // configured seat waits right here and fires within a tick of
                // that conn dropping. Checked on the cached identity, so parking
                // costs a string scan — never a resolver call.
                if ((c->hip[0]  && conn_host_live(conns, c, c->hip)) ||
                    (c->host[0] && conn_host_live(conns, c, c->host))) {
                    if (c->mesh_seat || c->chain_seat) {
                        c->outbound = 0; c->mesh_seat = 0; c->chain_seat = 0;
                        c->host[0] = 0; c->hip[0] = 0;
                    }
                    continue;
                }
                // actually dialing now — (re)resolve a hostname seat first, every
                // attempt, so the configured seed follows a DNS change across
                // redials. The numeric result is the dial target AND the identity
                // every dedup above compares; the hostname itself never reaches a
                // socket or the addr book.
                if (!c->hip[0] || strcmp(c->hip, c->host) != 0) {
                    if (!net_resolve_str(c->host, c->hip, sizeof c->hip)) {
                        c->hip[0] = 0;             // a stale ip must not pose as the identity
                        c->redial_at = now + 15;   // dns down: quiet retry (configured-seat idiom)
                        continue;
                    }
                    if (conn_host_live(conns, c, c->hip)) continue;   // fresh ip already held — park
                }
                // never dial a peer that resolves to ourselves — this node IS the
                // seed the hostname points at (no hairpin: the dial would just
                // time out on a loop back to us)
                if (host_is_self(c->hip, self)) {
                    fprintf(stderr, "serve: %s resolves to our own address %s — dropping self-seed\n",
                            c->host, *self ? self : g_self_ip);
                    if (!c->chain_seat) idx_self_seed = 1;   // a looping configured seed = we ARE the seed
                    c->outbound = 0; c->mesh_seat = 0; c->chain_seat = 0; c->host[0] = 0; c->hip[0] = 0; continue;
                }
                char agent[128]; int64_t psvc = 0, ph = 0;
                int fd = serve_dial(c->hip, c->rport, coin, services, our_h, agent, &psvc,
                                    self, port, &ph);
                if (fd == -2) {   // handshake proved the peer is us — drop it for good
                    fprintf(stderr, "serve: %s:%u is ourselves (self-connect) — dropping self-seed\n", c->host, c->rport);
                    if (!c->chain_seat) idx_self_seed = 1;
                    c->outbound = 0; c->mesh_seat = 0; c->chain_seat = 0; c->host[0] = 0; c->hip[0] = 0; continue;
                }
                if (fd < 0) {
                    // any pool-selected seat (mesh or chain): stamp the failure —
                    // the addr sits out DIAL_RETRY_S — and free the seat so the
                    // next tick offers a different candidate. Never hold a seat
                    // redialing one dead addr every 15s: an outbound-only peer
                    // announcing a port it can't serve would pin it forever.
                    if (c->chain_seat || c->mesh_seat) {
                        char addr[96]; snprintf(addr, sizeof addr, "%s:%u", c->host, c->rport);
                        idx_db_peer_tried(db, addr, (int64_t)now);
                        if (c->mesh_seat)   // small curated pool — one line per backoff window
                            fprintf(stderr, "serve: dial %s failed — backing off %ds  [mesh]\n",
                                    addr, DIAL_RETRY_S);
                        c->outbound = 0; c->mesh_seat = 0; c->chain_seat = 0; c->host[0] = 0; c->hip[0] = 0;
                        continue;
                    }
                    c->redial_at = now + 15; continue;   // configured peer: keep trying
                }
                c->fd = fd; c->up = 1; c->sent_ver = 1; c->magic = coin->magic;
                c->last_rx = now; c->last_ping = 0; c->peer_h = ph;
                // record the CONNECTED remote addr — the addr book stays numeric,
                // and the seat identity snaps to where the socket actually landed
                // (a multi-A-record name can resolve one way and connect another)
                net_peer_str(fd, c->peer, sizeof c->peer);
                char pip[80]; snprintf(pip, sizeof pip, "%s", c->peer);
                { char *pc = strrchr(pip, ':'); if (pc) *pc = 0; }
                snprintf(c->hip, sizeof c->hip, "%s", pip);
                // belt-and-braces: the pre-dial park makes this unreachable unless
                // the connect landed on an address no dedup could see in advance
                if (conn_host_live(conns, c, pip)) {
                    fprintf(stderr, "serve: %s is %s — already connected, dropping duplicate\n",
                            c->host, c->peer);
                    close(fd); c->fd = -1; c->up = 0;
                    if (c->mesh_seat || c->chain_seat) {
                        c->outbound = 0; c->mesh_seat = 0; c->chain_seat = 0; c->host[0] = 0; c->hip[0] = 0;
                    } else c->redial_at = now + 60;   // configured pin: the park then holds it
                    continue;
                }
                snprintf(c->agent, sizeof c->agent, "%s", agent);
                int is_dn = AGENT_MARKED(agent);
                // persist the handshake so a restart re-seats this peer from memory
                idx_db_peer_seen(db, c->peer, psvc, agent, (int64_t)now);
                // an overlay-seated slot whose peer isn't (any longer) marked was a
                // stale vouch — free the seat for a real one rather than redial forever
                if (c->mesh_seat && !is_dn) {
                    fprintf(stderr, "serve: %s lacks the " IDX_DNET_MARK " mark (agent %s) — releasing mesh seat\n", c->peer, *agent ? agent : "(none)");
                    close(fd); c->fd = -1; c->outbound = 0; c->mesh_seat = 0; c->host[0] = 0; c->hip[0] = 0; c->up = 0;
                    continue;
                }
                fprintf(stderr, "serve: dialed %s (agent %s)%s%s\n", c->peer, agent,
                        c->mesh_seat ? "  [mesh]" : "", c->chain_seat ? "  [chain]" : "");
                if (mesh && mesh->peer_up && !c->mesh_handle && is_dn)
                    c->mesh_handle = mesh->peer_up(mesh->ud, c, serve_mesh_send);
                if (!c->dn_asked && is_dn) {          // solicit its overlay peer list
                    net_send(fd, coin->magic, "dngetaddr", NULL, 0);
                    c->dn_asked = 1;
                }
                // self-announcement (see serve_announce_self) — once per connection
                if (port && *self && !c->self_sent) {
                    serve_announce_self(c, coin, self, services);
                    c->self_sent = 1;
                }
            }
        }
        if (mesh && mesh->tick) mesh->tick(mesh->ud);

        struct pollfd pfd[SERVE_MAX_CONN + 1]; int map[SERVE_MAX_CONN + 1]; int np = 0;
        if (lfd >= 0) { pfd[np].fd = lfd; pfd[np].events = POLLIN; map[np] = -1; np++; }
        for (int i = 0; i < SERVE_MAX_CONN; i++)
            if (conns[i].fd >= 0) { pfd[np].fd = conns[i].fd; pfd[np].events = POLLIN; map[np] = i; np++; }
        if (poll(pfd, np, 1000) <= 0) continue;
        int start = 0;
        if (lfd >= 0 && (pfd[0].revents & POLLIN)) {
            int cfd = accept(lfd, NULL, NULL);
            if (cfd >= 0) {
                char ip[INET_ADDRSTRLEN] = ""; unsigned rport = 0;
                struct sockaddr_in pa; socklen_t pl2 = sizeof pa;
                if (getpeername(cfd, (struct sockaddr *)&pa, &pl2) == 0) {
                    inet_ntop(AF_INET, &pa.sin_addr, ip, sizeof ip);
                    rport = ntohs(pa.sin_port);
                }
                int from_host = 0;
                for (int i = 0; i < SERVE_MAX_CONN; i++)
                    if (conns[i].fd >= 0 && !conns[i].outbound && ip[0] &&
                        !strncmp(conns[i].peer, ip, strlen(ip)) &&
                        conns[i].peer[strlen(ip)] == ':') from_host++;
                int slot = -1;
                for (int i = 0; i < SERVE_MAX_CONN; i++) if (conns[i].fd < 0 && !conns[i].outbound) { slot = i; break; }
                if (slot < 0 || from_host >= SERVE_INBOUND_PER_HOST) {
                    // rate-limited: an old-build peer bounces its transients off
                    // the cap every few seconds — one line a minute, not a flood
                    static time_t refuse_log_at = 0;
                    if (from_host >= SERVE_INBOUND_PER_HOST && now - refuse_log_at >= 60) {
                        refuse_log_at = now;
                        fprintf(stderr, "serve: %s:%u refused — host already connected (%d/host cap)\n",
                                ip, rport, SERVE_INBOUND_PER_HOST);
                    }
                    close(cfd);
                } else {
                    memset(&conns[slot], 0, sizeof conns[slot]);
                    conns[slot].fd = cfd; conns[slot].magic = coin->magic;
                    conns[slot].last_rx = time(NULL);   // handshake clock starts now
                    if (ip[0]) snprintf(conns[slot].peer, 80, "%s:%u", ip, rport);
                }
            }
        }
        if (lfd >= 0) start = 1;
        for (int k = start; k < np; k++) {
            if (map[k] < 0 || !(pfd[k].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            SConn *c = &conns[map[k]];
            uint8_t chunk[8192];
            ssize_t r = recv(c->fd, chunk, sizeof chunk, 0);
            if (r <= 0) { serve_drop(c, mesh); continue; }
            c->last_rx = time(NULL);
            size_t need = c->len + (size_t)r;
            if (need > SERVE_MSG_MAX + 1024u) { serve_drop(c, mesh); continue; }
            if (need > c->cap) {
                size_t nc = c->cap ? c->cap : 16384;
                while (nc < need) nc *= 2;
                uint8_t *nb = realloc(c->buf, nc);
                if (!nb) { serve_drop(c, mesh); continue; }
                c->buf = nb; c->cap = nc;
            }
            memcpy(c->buf + c->len, chunk, (size_t)r); c->len += (size_t)r;
            size_t off = 0; int dead = 0;
            while (c->len - off >= 24) {
                uint8_t *h = c->buf + off;
                if (memcmp(h, coin->magic, 4) != 0) { serve_drop(c, mesh); dead = 1; break; }
                uint32_t plen = (uint32_t)h[16] | (uint32_t)h[17] << 8 | (uint32_t)h[18] << 16 | (uint32_t)h[19] << 24;
                if (plen > SERVE_MSG_MAX) { serve_drop(c, mesh); dead = 1; break; }
                if (c->len - off < 24u + plen) break;
                char cmd[13]; memcpy(cmd, h + 4, 12); cmd[12] = 0;
                serve_dispatch(c, conns, coin, db, ss, services, cmd, h + 24, plen, self, port, mesh);
                if (c->fd < 0) { dead = 1; break; }   // dispatch dropped us
                off += 24u + plen;
            }
            if (!dead && off > 0) { memmove(c->buf, c->buf + off, c->len - off); c->len -= off; }
        }
    }
    for (int i = 0; i < SERVE_MAX_CONN; i++) if (conns[i].fd >= 0) serve_drop(&conns[i], mesh);
    if (lfd >= 0) close(lfd);
    g_conns.seq++; g_conns.n = 0; g_conns.seq++;      // serve is down — clear the page
    serve_store_close(ss); idx_db_close(db);
    return 0;
}

// ── crawl: explore the chain graph, classify peers by agent (discovery slice 2) ─
// One bounded pass: dial up to max_dials candidates — explicit `extra` targets
// first (comma list), then the table's least-recently-tried addrs — handshake,
// record services + agent + last_good, getaddr to grow the frontier. The
// classifier: the IDX_DNET_MARK subver prefix marks a dns-aware node (the mesh
// bucket); NODE_NETWORK services mark a block source (the sync bucket).
//
// Probes run CRAWL_PAR at a time on one poll loop (nonblocking connect, the
// same multiplexing idx_serve uses) with tight per-state budgets — a frontier
// full of dead addrs costs seconds per batch, not minutes per pass. Each
// probe: connect → version/verack (capture subver + services) → one getaddr,
// harvest the reply, close.
// Returns the number of marked peers now known in the db, -1 on open failure.
#define CRAWL_PAR         8            // concurrent probes
#define CRAWL_CONNECT_S   3            // connect budget
#define CRAWL_HANDSHAKE_S 5            // version/verack budget after connect
#define CRAWL_ADDR_S      2            // getaddr listen after handshake
#define CRAWL_BUF_MAX     (256 * 1024) // per-probe inbound cap (addr ≈ 30 KB)

typedef struct {
    int      fd;                       // -1 = slot free
    int      state;                    // 1 connecting · 2 handshaking · 3 addr wait
    int      got_ver, got_verack;
    time_t   deadline;
    char     cand[80], peer[80];       // dial target · resolved ip:port
    char     agent[128];
    uint64_t services;
    uint8_t *buf; size_t len, cap;     // frame accumulator (frames span reads)
} CrawlProbe;

static void probe_close(CrawlProbe *p) {
    if (p->fd >= 0) close(p->fd);
    free(p->buf);
    memset(p, 0, sizeof *p);
    p->fd = -1;
}

// start a nonblocking IPv4 connect; completion is signaled by POLLOUT. A
// hostname candidate (an explicit `extra` target) resolves synchronously —
// the db frontier is numeric ip:port text, so this stays off the hot path.
static int probe_connect_start(const char *host, uint16_t port) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        char ps[8]; snprintf(ps, sizeof ps, "%u", port);
        if (getaddrinfo(host, ps, &hints, &res) != 0 || !res) return -1;
        sa = *(struct sockaddr_in *)res->ai_addr;
        sa.sin_port = htons(port);
        freeaddrinfo(res);
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

int idx_crawl(const char *coinname, const char *dbpath, const char *extra,
              int max_dials, volatile int *stop) {
    const Coin *coin = coin_by_name(coinname); if (!coin) return -1;
    sqlite3 *db = idx_db_open(dbpath); if (!db) return -1;
    char cand[128][80]; int nc = 0;
    if (extra && *extra) {
        char list[512]; snprintf(list, sizeof list, "%s", extra);
        for (char *sv, *t = strtok_r(list, ",", &sv); t; t = strtok_r(NULL, ",", &sv))
            nc = cand_add(cand, nc, 128, t);
    }
    // frontier: never-tried first, then stalest — a fresh harvest gets explored
    // before yesterday's dead addrs get re-poked
    { char pool[128][80]; int n = idx_db_peers_crawl(db, pool, 128 - nc);
      for (int i = 0; i < n; i++) nc = cand_add(cand, nc, 128, pool[i]); }
    int dials = 0, up = 0, pepenet_hits = 0, next_cand = 0;
    CrawlProbe pr[CRAWL_PAR];
    for (int i = 0; i < CRAWL_PAR; i++) { memset(&pr[i], 0, sizeof pr[i]); pr[i].fd = -1; }
    g_crawl.seq++;                                    // pass starts (live progress)
    g_crawl.s.running = 1;
    g_crawl.s.dials = 0; g_crawl.s.up = 0; g_crawl.s.hits = 0;
    g_crawl.s.max_dials = max_dials < nc ? max_dials : nc;
    g_crawl.s.last_peer[0] = 0; g_crawl.s.last_agent[0] = 0;
    g_crawl.seq++;
    while (!(stop && *stop)) {
        time_t now = time(NULL);
        // kick candidates into free probe slots
        for (int i = 0; i < CRAWL_PAR && next_cand < nc && dials < max_dials; i++) {
            CrawlProbe *p = &pr[i];
            if (p->fd >= 0) continue;
            const char *ct = cand[next_cand++];
            dials++;
            idx_db_peer_tried(db, ct, (int64_t)now);
            g_crawl.seq++;                            // probing this candidate
            g_crawl.s.dials = dials;
            snprintf(g_crawl.s.last_peer, sizeof g_crawl.s.last_peer, "%s", ct);
            g_crawl.s.last_agent[0] = 0;
            g_crawl.seq++;
            char host[80]; uint16_t port;
            peer_split(ct, host, sizeof host, &port, coin->port);
            int fd = probe_connect_start(host, port);
            if (fd < 0) { fprintf(stderr, "  %s:%u down\n", host, port); continue; }
            memset(p, 0, sizeof *p);
            p->fd = fd; p->state = 1; p->deadline = now + CRAWL_CONNECT_S;
            snprintf(p->cand, sizeof p->cand, "%s:%u", host, port);
        }
        int live = 0;
        for (int i = 0; i < CRAWL_PAR; i++) if (pr[i].fd >= 0) live++;
        if (!live) {
            if (next_cand >= nc || dials >= max_dials) break;
            continue;                                 // every kick failed — refill
        }
        struct pollfd pfd[CRAWL_PAR]; int map[CRAWL_PAR]; int np = 0;
        for (int i = 0; i < CRAWL_PAR; i++)
            if (pr[i].fd >= 0) {
                pfd[np].fd = pr[i].fd;
                pfd[np].events = pr[i].state == 1 ? POLLOUT : POLLIN;
                pfd[np].revents = 0;
                map[np] = i; np++;
            }
        poll(pfd, np, 250);
        now = time(NULL);
        for (int k = 0; k < np; k++) {
            CrawlProbe *p = &pr[map[k]];
            if (p->state == 1) {                      // connect completing?
                if (!(pfd[k].revents & (POLLOUT | POLLERR | POLLHUP))) continue;
                int err = 0; socklen_t el = sizeof err;
                if ((pfd[k].revents & (POLLERR | POLLHUP)) ||
                    getsockopt(p->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
                    fprintf(stderr, "  %s down\n", p->cand);
                    probe_close(p);
                    continue;
                }
                int fl = fcntl(p->fd, F_GETFL, 0);
                fcntl(p->fd, F_SETFL, fl & ~O_NONBLOCK);   // sends are tiny; block them
                net_peer_str(p->fd, p->peer, sizeof p->peer);
                serve_send_version(p->fd, coin, 0, 0);     // WE speak first
                p->state = 2; p->deadline = now + CRAWL_HANDSHAKE_S;
                continue;
            }
            if (!(pfd[k].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            uint8_t chunk[8192];
            ssize_t r = recv(p->fd, chunk, sizeof chunk, 0);
            if (r <= 0) {
                if (p->state == 2) fprintf(stderr, "  %s no handshake\n", p->cand);
                probe_close(p);
                continue;
            }
            size_t need = p->len + (size_t)r;
            if (need > CRAWL_BUF_MAX) { probe_close(p); continue; }
            if (need > p->cap) {
                size_t ncap = p->cap ? p->cap : 8192;
                while (ncap < need) ncap *= 2;
                uint8_t *nb = realloc(p->buf, ncap);
                if (!nb) { probe_close(p); continue; }
                p->buf = nb; p->cap = ncap;
            }
            memcpy(p->buf + p->len, chunk, (size_t)r); p->len += (size_t)r;
            size_t off = 0; int dead = 0, harvested = 0;
            while (p->len - off >= 24) {
                uint8_t *h = p->buf + off;
                if (memcmp(h, coin->magic, 4) != 0) { dead = 1; break; }
                uint32_t plen = (uint32_t)h[16] | (uint32_t)h[17] << 8 |
                                (uint32_t)h[18] << 16 | (uint32_t)h[19] << 24;
                if (plen > CRAWL_BUF_MAX) { dead = 1; break; }
                if (p->len - off < 24u + plen) break;
                char cmd[13]; memcpy(cmd, h + 4, 12); cmd[12] = 0;
                uint8_t *pl = h + 24;
                if (!strcmp(cmd, "version")) {
                    uint64_t vn;                          // crawled our own address?
                    if (ver_nonce(pl, plen, &vn) && vn == self_nonce()) { dead = 1; break; }
                    learn_self_ip(pl, plen);              // real peer's addr_recv = our external ip
                    if (plen >= 12) {
                        uint64_t sv = 0;
                        for (int b = 0; b < 8; b++) sv |= (uint64_t)pl[4 + b] << (8 * b);
                        p->services = sv;
                    }
                    uint64_t o2 = 4 + 8 + 8 + 26 + 26 + 8, ua;
                    if (plen > o2) {
                        ua = pl[o2++];
                        if (ua == 0xFD && plen >= o2 + 2) { ua = pl[o2] | (pl[o2+1] << 8); o2 += 2; }
                        if (ua <= 100 && plen >= o2 + ua) { memcpy(p->agent, pl + o2, ua); p->agent[ua] = 0; }
                    }
                    net_send(p->fd, coin->magic, "verack", NULL, 0);
                    p->got_ver = 1;
                } else if (!strcmp(cmd, "verack")) {
                    p->got_verack = 1;
                } else if (!strcmp(cmd, "ping")) {
                    net_send(p->fd, coin->magic, "pong", pl, plen);
                } else if (!strcmp(cmd, "addr") && p->state == 3) {
                    addr_harvest(db, pl, plen, 0);
                    harvested = 1;
                }
                off += 24u + plen;
            }
            if (dead) { probe_close(p); continue; }
            if (off > 0) { memmove(p->buf, p->buf + off, p->len - off); p->len -= off; }
            if (p->state == 2 && p->got_ver && p->got_verack) {
                up++;
                idx_db_peer_seen(db, p->peer, (int64_t)p->services, p->agent, (int64_t)now);
                int is_pepenet = AGENT_MARKED(p->agent);
                if (is_pepenet) pepenet_hits++;
                g_crawl.seq++;                        // handshake landed
                g_crawl.s.up = up; g_crawl.s.hits = pepenet_hits;
                snprintf(g_crawl.s.last_peer, sizeof g_crawl.s.last_peer, "%s", p->peer);
                snprintf(g_crawl.s.last_agent, sizeof g_crawl.s.last_agent, "%s", p->agent);
                g_crawl.seq++;
                fprintf(stderr, "  %s up  agent %s  services 0x%llx%s\n", p->peer,
                        p->agent[0] ? p->agent : "(none)",
                        (unsigned long long)p->services,
                        is_pepenet ? "  [" IDX_DNET_MARK "]" : "");
                // grow the frontier: one getaddr, listen briefly for the reply
                net_send(p->fd, coin->magic, "getaddr", NULL, 0);
                p->state = 3; p->deadline = now + CRAWL_ADDR_S;
            }
            if (harvested) probe_close(p);
        }
        for (int i = 0; i < CRAWL_PAR; i++) {         // expire per-state budgets
            CrawlProbe *p = &pr[i];
            if (p->fd < 0 || now < p->deadline) continue;
            if (p->state == 1)      fprintf(stderr, "  %s down (timeout)\n", p->cand);
            else if (p->state == 2) fprintf(stderr, "  %s no handshake\n", p->cand);
            probe_close(p);                           // state 3: already recorded up
        }
    }
    for (int i = 0; i < CRAWL_PAR; i++) probe_close(&pr[i]);
    char dn[16][80]; int ndn = idx_db_peers_agent(db, IDX_DNET_MARK, dn, 16);
    fprintf(stderr, "crawl: %d dialed, %d up, %d " IDX_DNET_MARK " this pass (%d known total)\n",
            dials, up, pepenet_hits, ndn);
    g_crawl.seq++;                                    // pass over
    g_crawl.s.running = 0;
    g_crawl.s.dials = dials; g_crawl.s.up = up; g_crawl.s.hits = pepenet_hits;
    g_crawl.s.known = ndn;
    g_crawl.s.last_pass = (int64_t)time(NULL);
    g_crawl.s.passes++;
    g_crawl.seq++;
    idx_db_close(db);
    return ndn;
}

static int cmd_serve(int argc, char **argv) {
    // serve <coin> <db> [port] [dial_peers]  (standalone: chain data only, no mesh)
    if (argc < 4) { fprintf(stderr, "usage: serve <doge|pep|testnet|regtest> <db> [port] [host:port,...]\n"); return 2; }
    const Coin *coin = coin_by_name(argv[2]); if (!coin) { fprintf(stderr, "unknown coin %s\n", argv[2]); return 2; }
    uint16_t port = argc > 4 ? (uint16_t)atoi(argv[4]) : coin->port;
    const char *dial = argc > 5 ? argv[5] : NULL;
    return idx_serve(argv[2], argv[3], port, dial, &idx_sync_stop, NULL) < 0 ? 1 : 0;
}

static int cmd_crawl(int argc, char **argv) {
    // crawl <coin> <db> [max_dials=8] [extra,targets]
    if (argc < 4) { fprintf(stderr, "usage: crawl <doge|pep|testnet|regtest> <db> [max_dials=8] [host:port,...]\n"); return 2; }
    int max_dials = argc > 4 ? atoi(argv[4]) : 8;
    int n = idx_crawl(argv[2], argv[3], argc > 5 ? argv[5] : NULL, max_dials, &idx_sync_stop);
    if (n < 0) { fprintf(stderr, "cannot open %s\n", argv[3]); return 1; }
    char dn[16][80]; sqlite3 *db = idx_db_open(argv[3]);
    if (db) {
        int k = idx_db_peers_agent(db, IDX_DNET_MARK, dn, 16);
        for (int i = 0; i < k; i++) printf("%s %s\n", IDX_DNET_MARK, dn[i]);
        idx_db_close(db);
    }
    return 0;
}

int indexer_main(int argc, char **argv) {
    const char *cmd = argv[1];
    if (!strcmp(cmd, "index"))   return cmd_index(argc, argv);
    if (!strcmp(cmd, "resolve")) return cmd_resolve(argc, argv);
    if (!strcmp(cmd, "owned"))   return cmd_owned(argc, argv);
    if (!strcmp(cmd, "digest"))  return cmd_digest(argc, argv);
    if (!strcmp(cmd, "refold"))  return cmd_refold(argc, argv);
    if (!strcmp(cmd, "watch"))   return cmd_watch(argc, argv);
    if (!strcmp(cmd, "sync"))    return cmd_sync(argc, argv);
    if (!strcmp(cmd, "crawl"))   return cmd_crawl(argc, argv);
    if (!strcmp(cmd, "serve"))   return cmd_serve(argc, argv);
    if (!strcmp(cmd, "weigh"))   return cmd_weigh(argc, argv);
    return 2;
}

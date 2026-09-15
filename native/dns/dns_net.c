/* dns_net.c — see dns_net.h. */
#include "dns_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pepenet/wire.h"
#include "pepenet/crypto.h"

#define MAX_PEERS   64
#define HOLD_SLOTS  64
#define HOLD_TTL_S  120
#define INV_BATCH   64          /* names per dnzinv frame */
#define AE_PERIOD_S 60          /* anti-entropy: re-inv the store this often */

typedef struct {
    void          *peer;
    dnsnet_send_fn send;
    int            used;
} Peer;

typedef struct {
    uint8_t blob[SP_STATE_OP_MAX];
    int     len;
    time_t  expiry;
} Held;

static struct {
    SpState      *st;
    SpChainOracle o;
    int           verbose;
    Peer          peers[MAX_PEERS];
    Held          hold[HOLD_SLOTS];
    time_t        next_ae;
} g;

void dnsnet_init(SpState *st, SpChainOracle oracle, int verbose) {
    memset(&g, 0, sizeof g);
    g.st = st; g.o = oracle; g.verbose = verbose;
}

int dnsnet_peers(void) {
    int n = 0;
    for (int i = 0; i < MAX_PEERS; i++) if (g.peers[i].used) n++;
    return n;
}

/* ── senders ─────────────────────────────────────────────────────────────────── */
typedef struct { uint8_t buf[16 + INV_BATCH * (1 + SP_NAME_MAX + 32)]; int off, count; Peer *to; } InvAcc;

static void inv_flush(InvAcc *a) {
    if (!a->count) return;
    uint8_t hdr[8]; int hn = sp_wvar(hdr, (uint64_t)a->count);
    uint8_t out[sizeof a->buf + 8];
    memcpy(out, hdr, (size_t)hn);
    memcpy(out + hn, a->buf, (size_t)a->off);
    if (a->to) {
        if (a->to->used) a->to->send(a->to->peer, "dnzinv", out, (size_t)(hn + a->off));
    } else {
        for (int i = 0; i < MAX_PEERS; i++)
            if (g.peers[i].used) g.peers[i].send(g.peers[i].peer, "dnzinv", out, (size_t)(hn + a->off));
    }
    a->off = 0; a->count = 0;
}

static void inv_add(InvAcc *a, const char *name) {
    int nlen = (int)strlen(name);
    if (nlen < 1 || nlen > SP_NAME_MAX) return;
    a->buf[a->off++] = (uint8_t)nlen;
    memcpy(a->buf + a->off, name, (size_t)nlen); a->off += nlen;
    dns_state_digest(g.st, name, a->buf + a->off); a->off += 32;
    if (++a->count >= INV_BATCH) inv_flush(a);
}

static int inv_all_cb(void *u, const char *name) { inv_add(u, name); return 1; }

static void send_inv_all(Peer *to) {
    static InvAcc a;                        /* single-threaded (net thread) */
    a.off = 0; a.count = 0; a.to = to;
    sp_state_names(g.st, inv_all_cb, &a);
    inv_flush(&a);
}

typedef struct { uint8_t *buf; int off, cap, count; } DatAcc;

static int dat_cb(void *u, const uint8_t *key, int klen, int op,
                  uint32_t anchor, const uint8_t *blob, int blen) {
    (void)key; (void)klen; (void)op; (void)anchor;
    DatAcc *a = u;
    uint8_t hdr[8]; int hn = sp_wvar(hdr, (uint64_t)blen);
    if (a->off + hn + blen > a->cap) return 0;
    memcpy(a->buf + a->off, hdr, (size_t)hn); a->off += hn;
    memcpy(a->buf + a->off, blob, (size_t)blen); a->off += blen;
    a->count++;
    return 1;
}

static void send_zdat(Peer *to, const char *name) {
    int nlen = (int)strlen(name);
    if (nlen < 1 || nlen > SP_NAME_MAX || !to->used) return;
    /* budgeted zone + clear op + per-op length prefixes: 2× budget is ample */
    static uint8_t frame[2 * DNS_BUDGET + 64];
    static uint8_t body[2 * DNS_BUDGET];
    DatAcc a = { body, 0, sizeof body, 0 };
    uint8_t *cb; int cl;
    if (sp_state_clear_get(g.st, name, &cb, &cl)) {   /* clear FIRST: floor before rows */
        dat_cb(&a, NULL, 0, SP_OP_CLEAR, 0, cb, cl);
        free(cb);
    }
    sp_state_iter(g.st, name, dat_cb, &a);
    int o = 0;
    frame[o++] = (uint8_t)nlen;
    memcpy(frame + o, name, (size_t)nlen); o += nlen;
    o += sp_wvar(frame + o, (uint64_t)a.count);
    memcpy(frame + o, body, (size_t)a.off); o += a.off;
    to->send(to->peer, "dnzdat", frame, (size_t)o);
}

void dnsnet_announce(const char *name) {
    static InvAcc a;
    a.off = 0; a.count = 0; a.to = NULL;    /* broadcast */
    inv_add(&a, name);
    inv_flush(&a);
}

static void send_inv_one(Peer *to, const char *name) {
    static InvAcc a;
    a.off = 0; a.count = 0; a.to = to;
    inv_add(&a, name);
    inv_flush(&a);
}

/* ── hold queue (ops anchored ahead of our sync) ─────────────────────────────── */
static void hold_push(const uint8_t *op, int len) {
    for (int i = 0; i < HOLD_SLOTS; i++)
        if (!g.hold[i].len) {
            memcpy(g.hold[i].blob, op, (size_t)len);
            g.hold[i].len = len;
            g.hold[i].expiry = time(NULL) + HOLD_TTL_S;
            return;
        }
}

static void hold_service(void) {
    time_t now = time(NULL);
    char err[128];
    for (int i = 0; i < HOLD_SLOTS; i++) {
        if (!g.hold[i].len) continue;
        if (g.hold[i].expiry <= now) { g.hold[i].len = 0; continue; }
        int rc = sp_state_admit(g.st, &g.o, DNS_BUDGET, DNS_SCOPE,
                                g.hold[i].blob, g.hold[i].len, err, sizeof err);
        if (rc == -2) continue;             /* still ahead — keep holding */
        if (rc == 1) {
            SpStateOp p;
            if (sp_state_op_parse(g.hold[i].blob, g.hold[i].len, &p)) {
                char name[SP_NAME_MAX + 1];
                memcpy(name, p.name, (size_t)p.name_len); name[p.name_len] = '\0';
                dnsnet_announce(name);
            }
        }
        g.hold[i].len = 0;                  /* admitted / rejected / dup — done */
    }
}

/* ── receive ─────────────────────────────────────────────────────────────────── */
static void on_zinv(Peer *from, const uint8_t *pay, int n) {
    int off = 0; uint64_t count;
    if (!sp_rvar(pay, n, &off, &count) || count > 4096) return;
    for (uint64_t i = 0; i < count; i++) {
        if (off + 1 > n) return;
        int nlen = pay[off++];
        if (nlen < 1 || nlen > SP_NAME_MAX || off + nlen + 32 > n) return;
        char name[SP_NAME_MAX + 1];
        memcpy(name, pay + off, (size_t)nlen); name[nlen] = '\0'; off += nlen;
        const uint8_t *their = pay + off; off += 32;
        if (!sp_name_valid(name, (size_t)nlen)) continue;
        uint8_t ours[32];
        dns_state_digest(g.st, name, ours);
        if (memcmp(ours, their, 32) != 0) {
            uint8_t req[1 + SP_NAME_MAX]; int ro = 0;
            req[ro++] = (uint8_t)nlen;
            memcpy(req + ro, name, (size_t)nlen); ro += nlen;
            from->send(from->peer, "dnzget", req, (size_t)ro);
        }
    }
}

static void on_zget(Peer *from, const uint8_t *pay, int n) {
    if (n < 1) return;
    int nlen = pay[0];
    if (nlen < 1 || nlen > SP_NAME_MAX || 1 + nlen > n) return;
    char name[SP_NAME_MAX + 1];
    memcpy(name, pay + 1, (size_t)nlen); name[nlen] = '\0';
    if (!sp_name_valid(name, (size_t)nlen)) return;
    send_zdat(from, name);
}

static void on_zdat(Peer *from, const uint8_t *pay, int n) {
    if (n < 1) return;
    int off = 0;
    int nlen = pay[off++];
    if (nlen < 1 || nlen > SP_NAME_MAX || off + nlen > n) return;
    char name[SP_NAME_MAX + 1];
    memcpy(name, pay + off, (size_t)nlen); name[nlen] = '\0'; off += nlen;
    if (!sp_name_valid(name, (size_t)nlen)) return;
    uint64_t count;
    if (!sp_rvar(pay, n, &off, &count) || count > 1024) return;
    int changed = 0;
    char err[128];
    for (uint64_t i = 0; i < count; i++) {
        uint64_t ol;
        if (!sp_rvar(pay, n, &off, &ol) || ol < 1 || ol > SP_STATE_OP_MAX || off + (int)ol > n) return;
        const uint8_t *op = pay + off; off += (int)ol;
        /* the frame's name must match the op's (one name per dump) */
        SpStateOp p;
        if (!sp_state_op_parse(op, (int)ol, &p) ||
            p.name_len != nlen || memcmp(p.name, name, (size_t)nlen) != 0) continue;
        int rc = sp_state_admit(g.st, &g.o, DNS_BUDGET, DNS_SCOPE, op, (int)ol, err, sizeof err);
        if (rc == 1) changed = 1;
        else if (rc == -2) hold_push(op, (int)ol);
        else if (rc == 0 && g.verbose)
            fprintf(stderr, "dnsnet: reject %s: %s\n", name, err);
    }
    if (changed) {
        /* announce to everyone — including the source: if we also hold ops it
         * lacked, its digest now mismatches ours and it pulls back. */
        dnsnet_announce(name);
    } else {
        /* nothing new for us — the source may be the stale side. Answer with
         * OUR digest for the name (cheap, idempotent); the source zgets from
         * us iff it actually differs, so an equal-state exchange goes silent
         * instead of ping-ponging dumps. */
        send_inv_one(from, name);
    }
}

/* ── the IdxMeshHooks mirror ─────────────────────────────────────────────────── */
void *dnsnet_up(void *peer, dnsnet_send_fn send) {
    for (int i = 0; i < MAX_PEERS; i++)
        if (!g.peers[i].used) {
            g.peers[i].peer = peer;
            g.peers[i].send = send;
            g.peers[i].used = 1;
            send_inv_all(&g.peers[i]);      /* our whole shelf, on connect */
            return &g.peers[i];
        }
    return NULL;
}

void dnsnet_msg(void *handle, const char *cmd, const uint8_t *pay, int n) {
    Peer *p = handle;
    if (!p || !p->used || n < 0) return;
    /* idx_serve strips the "dn" transport prefix before the hook (sync.c
     * serve_dispatch hands cmd + 2) — we send "dnzinv", we receive "zinv". */
    if      (!strcmp(cmd, "zinv")) on_zinv(p, pay, n);
    else if (!strcmp(cmd, "zget")) on_zget(p, pay, n);
    else if (!strcmp(cmd, "zdat")) on_zdat(p, pay, n);
}

void dnsnet_down(void *handle) {
    Peer *p = handle;
    if (p) { p->used = 0; p->peer = NULL; p->send = NULL; }
}

void dnsnet_tick(void) {
    hold_service();
    time_t now = time(NULL);
    if (!g.next_ae) g.next_ae = now + AE_PERIOD_S;
    if (now >= g.next_ae) {                 /* periodic anti-entropy re-inv */
        g.next_ae = now + AE_PERIOD_S;
        send_inv_all(NULL);                 /* broadcast to every live peer */
    }
}

/* dns_state.c — see dns_state.h. */
#include "dns_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include "pepenet/wire.h"
#include "pepenet/crypto.h"

static int fail3(char *err, int errlen, const char *m) {
    if (err && errlen > 0) snprintf(err, (size_t)errlen, "%s", m);
    return -3;
}

/* ── key / payload codecs ───────────────────────────────────────────────────── */
int dns_key_pack(const char *label, uint16_t type, uint8_t *key, int keymax) {
    int ll = label ? (int)strlen(label) : 0;
    if (ll > 63 || ll + 2 > keymax || ll + 2 > SP_STATE_KEY_MAX) return -1;
    for (int i = 0; i < ll; i++)
        key[i] = (uint8_t)tolower((unsigned char)label[i]);   /* DNS labels: case-blind */
    key[ll]     = (uint8_t)(type >> 8);
    key[ll + 1] = (uint8_t)(type & 0xFF);
    return ll + 2;
}

int dns_key_unpack(const uint8_t *key, int klen, char label[64], uint16_t *type) {
    if (klen < 2 || klen - 2 > 63) return 0;
    memcpy(label, key, (size_t)(klen - 2));
    label[klen - 2] = '\0';
    *type = (uint16_t)((key[klen - 2 + 0] << 8) | key[klen - 1]);
    return 1;
}

int dns_payload_pack(uint32_t ttl, const uint8_t *rdata, int rdlen,
                     uint8_t *out, int outmax) {
    uint8_t tmp[8];
    int n = sp_wvar(tmp, ttl);
    if (rdlen < 1 || n + rdlen > outmax) return -1;   /* empty rdata is a DEL, not a PUT */
    memcpy(out, tmp, (size_t)n);
    memcpy(out + n, rdata, (size_t)rdlen);
    return n + rdlen;
}

int dns_payload_unpack(const uint8_t *p, int plen, uint32_t *ttl,
                       const uint8_t **rdata, int *rdlen) {
    int off = 0; uint64_t v;
    if (!sp_rvar(p, plen, &off, &v) || v > 0xFFFFFFFFu) return 0;
    *ttl = (uint32_t)v;
    *rdata = p + off;
    *rdlen = plen - off;
    return *rdlen >= 1 && *rdlen <= ZONE_MAX_RDATA;
}

/* ── on-chain carrier (0xFF 'P' 'N' 0xD8) ───────────────────────────────────── */
int dns_rec_encode(const zone_rec *r, uint8_t *out, int outmax) {
    int o = 0, n; uint8_t tmp[8];
    if (outmax < 4) return -1;
    out[o++] = 0xFF; out[o++] = 'P'; out[o++] = 'N'; out[o++] = ZONE_OP;
    int ll = (int)strlen(r->label);
    n = sp_wvar(tmp, (uint64_t)ll);   if (o + n + ll > outmax) return -1; memcpy(out + o, tmp, n); o += n;
    memcpy(out + o, r->label, (size_t)ll); o += ll;
    n = sp_wvar(tmp, r->type);        if (o + n > outmax) return -1; memcpy(out + o, tmp, n); o += n;
    n = sp_wvar(tmp, r->ttl);         if (o + n > outmax) return -1; memcpy(out + o, tmp, n); o += n;
    if (o + r->rdlen > outmax) return -1;
    memcpy(out + o, r->rdata, r->rdlen); o += r->rdlen;
    return o;
}

int dns_rec_decode(const uint8_t *c, int clen, zone_rec *r) {
    if (clen < 4 || c[0] != 0xFF || c[1] != 'P' || c[2] != 'N' || c[3] != ZONE_OP) return 0;
    int off = 4; uint64_t ll, type, ttl;
    if (!sp_rvar(c, clen, &off, &ll) || ll >= sizeof r->label || off + (int)ll > clen) return 0;
    memcpy(r->label, c + off, (size_t)ll); r->label[ll] = '\0'; off += (int)ll;
    if (!sp_rvar(c, clen, &off, &type) || type > 0xFFFF) return 0;
    if (!sp_rvar(c, clen, &off, &ttl)) return 0;
    int rd = clen - off;
    if (rd < 0 || rd > ZONE_MAX_RDATA) return 0;
    r->type = (uint16_t)type;
    r->ttl  = (uint32_t)ttl;
    r->rdlen = (uint16_t)rd;
    if (rd) memcpy(r->rdata, c + off, (size_t)rd);
    return 1;
}

int dns_rec_escape_hatchable(const zone_rec *r) {
    uint8_t tmp[256];
    int n = dns_rec_encode(r, tmp, sizeof tmp);
    return n > 0 && n <= DNS_ONCHAIN_MAX;
}

/* ── publishing ─────────────────────────────────────────────────────────────── */
/* the publish anchor: tip − SP_STATE_REORG (or the tip itself on a young
 * chain), with its header hash from the oracle. 1 ok, 0 no usable anchor. */
static int publish_anchor(const SpChainOracle *o, uint32_t *height, uint8_t hash[32]) {
    uint32_t tip = o->tip(o->u);
    uint32_t h = tip > SP_STATE_REORG ? tip - SP_STATE_REORG : tip;
    if (o->header_at(o->u, h, hash) != 1) return 0;
    *height = h;
    return 1;
}

static int op_emit(SpState *st, const SpChainOracle *o, uint8_t opc,
                   const char *name, const uint8_t *key, int klen,
                   const uint8_t *payload, int plen,
                   const uint8_t priv[32], const uint8_t pub33[33],
                   int cert_type, const uint8_t *cert, int cert_len,
                   char *err, int errlen) {
    uint32_t ah; uint8_t hh[32];
    if (!publish_anchor(o, &ah, hh)) return fail3(err, errlen, "no usable anchor (chain not synced?)");
    uint8_t op[SP_STATE_OP_MAX];
    int n = sp_state_op_build(opc, name, key, klen, payload, plen, ah, hh,
                              priv, pub33, cert_type, cert, cert_len, op, sizeof op);
    if (n < 0) return fail3(err, errlen, "op build failed");
    return sp_state_admit(st, o, DNS_BUDGET, DNS_SCOPE, op, n, err, errlen);
}

int dns_state_put(SpState *st, const SpChainOracle *o, const char *name,
                  const zone_rec *rec,
                  const uint8_t priv[32], const uint8_t pub33[33],
                  int cert_type, const uint8_t *cert, int cert_len,
                  char *err, int errlen) {
    if (rec->rdlen == 0)   /* the old empty-PUT convention is now an explicit DEL */
        return dns_state_del(st, o, name, rec->label, rec->type,
                             priv, pub33, cert_type, cert, cert_len, err, errlen);
    uint8_t key[SP_STATE_KEY_MAX];
    int klen = dns_key_pack(rec->label, rec->type, key, sizeof key);
    if (klen < 0) return fail3(err, errlen, "label too long");
    uint8_t pay[8 + ZONE_MAX_RDATA];
    int plen = dns_payload_pack(rec->ttl, rec->rdata, rec->rdlen, pay, sizeof pay);
    if (plen < 0) return fail3(err, errlen, "rdata too long");
    return op_emit(st, o, SP_OP_PUT, name, key, klen, pay, plen,
                   priv, pub33, cert_type, cert, cert_len, err, errlen);
}

int dns_state_del(SpState *st, const SpChainOracle *o, const char *name,
                  const char *label, uint16_t type,
                  const uint8_t priv[32], const uint8_t pub33[33],
                  int cert_type, const uint8_t *cert, int cert_len,
                  char *err, int errlen) {
    uint8_t key[SP_STATE_KEY_MAX];
    int klen = dns_key_pack(label, type, key, sizeof key);
    if (klen < 0) return fail3(err, errlen, "label too long");
    return op_emit(st, o, SP_OP_DEL, name, key, klen, NULL, 0,
                   priv, pub33, cert_type, cert, cert_len, err, errlen);
}

int dns_state_clear(SpState *st, const SpChainOracle *o, const char *name,
                    const uint8_t priv[32], const uint8_t pub33[33],
                    int cert_type, const uint8_t *cert, int cert_len,
                    char *err, int errlen) {
    return op_emit(st, o, SP_OP_CLEAR, name, NULL, 0, NULL, 0,
                   priv, pub33, cert_type, cert, cert_len, err, errlen);
}

/* ── reads ──────────────────────────────────────────────────────────────────── */
static int zone_cb(void *u, const uint8_t *key, int klen, int op,
                   uint32_t anchor, const uint8_t *blob, int blen) {
    (void)anchor;
    zone *z = u;
    if (op != SP_OP_PUT || z->n >= ZONE_MAX_RECS) return 1;
    SpStateOp p;
    if (!sp_state_op_parse(blob, blen, &p)) return 1;
    zone_rec *r = &z->recs[z->n];
    uint16_t type; char label[64];
    if (!dns_key_unpack(key, klen, label, &type)) return 1;
    uint32_t ttl; const uint8_t *rd; int rdl;
    if (!dns_payload_unpack(p.payload, p.payload_len, &ttl, &rd, &rdl)) return 1;
    snprintf(r->label, sizeof r->label, "%s", label);
    r->type = type; r->ttl = ttl;
    r->rdlen = (uint16_t)rdl;
    memcpy(r->rdata, rd, (size_t)rdl);
    z->n++;
    return 1;
}

int dns_state_zone(SpState *st, const char *name, zone *z) {
    memset(z, 0, sizeof *z);
    size_t nlen = name ? strlen(name) : 0;
    if (!sp_name_valid(name, nlen)) return 0;
    snprintf(z->apex, sizeof z->apex, "%s", name);
    sp_state_iter(st, name, zone_cb, z);
    return z->n;
}

/* ── digest ─────────────────────────────────────────────────────────────────── */
typedef struct { uint8_t buf[4 + 32 + 32 * 512]; int off; } DigAcc;

static int dig_cb(void *u, const uint8_t *key, int klen, int op,
                  uint32_t anchor, const uint8_t *blob, int blen) {
    (void)key; (void)klen; (void)op; (void)anchor;
    DigAcc *a = u;
    if (a->off + 32 > (int)sizeof a->buf) return 0;
    SpStateOp p;
    if (sp_state_op_parse(blob, blen, &p)) { memcpy(a->buf + a->off, p.op_id, 32); a->off += 32; }
    return 1;
}

void dns_state_digest(SpState *st, const char *name, uint8_t out[32]) {
    static DigAcc a;                       /* big; single-threaded per store owner */
    a.off = 0;
    uint32_t f = sp_state_floor(st, name);
    a.buf[a.off++] = (uint8_t)f; a.buf[a.off++] = (uint8_t)(f >> 8);
    a.buf[a.off++] = (uint8_t)(f >> 16); a.buf[a.off++] = (uint8_t)(f >> 24);
    uint8_t *cb; int cl;
    if (sp_state_clear_get(st, name, &cb, &cl)) {
        SpStateOp p;
        if (sp_state_op_parse(cb, cl, &p)) { memcpy(a.buf + a.off, p.op_id, 32); a.off += 32; }
        free(cb);
    } else { memset(a.buf + a.off, 0, 32); a.off += 32; }
    sp_state_iter(st, name, dig_cb, &a);   /* key-ordered ⇒ canonical */
    sp_sha256(a.buf, (size_t)a.off, out);
}

/* ── sweep ──────────────────────────────────────────────────────────────────── */
typedef struct { char names[256][SP_NAME_MAX + 1]; int n; } SweepAcc;

static int sweep_cb(void *u, const char *name) {
    SweepAcc *a = u;
    if (a->n >= 256) return 0;             /* next daily pass gets the rest */
    snprintf(a->names[a->n++], SP_NAME_MAX + 1, "%s", name);
    return 1;
}

int dns_state_sweep(SpState *st, const SpChainOracle *o) {
    SweepAcc a; a.n = 0;
    sp_state_names(st, sweep_cb, &a);
    int dropped = 0;
    uint8_t owner[20];
    for (int i = 0; i < a.n; i++)
        if (!o->owner_now(o->u, a.names[i], owner)) {
            sp_state_drop_name(st, a.names[i]);
            dropped++;
        }
    return dropped;
}

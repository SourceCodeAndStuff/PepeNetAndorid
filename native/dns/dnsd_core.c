/* dnsd_core.c — the resolver core (see dnsd_core.h). Moved verbatim from
 * dnsd.c's main-thread half, with the file-scope globals folded into DnsdCore. */
#include "dnsd_core.h"
#include "dns_wire.h"
#include "pepenet/crypto.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

static void split_apex(const char *left, char *apex, size_t acap, char *sub, size_t scap) {
    const char *dot = strrchr(left, '.');
    if (dot) {
        snprintf(apex, acap, "%s", dot + 1);
        size_t n = (size_t)(dot - left); if (n >= scap) n = scap - 1;
        memcpy(sub, left, n); sub[n] = '\0';
    } else { snprintf(apex, acap, "%s", left); sub[0] = '\0'; }
}

/* Does `sub` publish a DANE record at _443._tcp? (drives tls_redirect.) */
static int has_443_tlsa(const zone *z, const char *sub) {
    char lbl[80];
    if (*sub) snprintf(lbl, sizeof lbl, "_443._tcp.%s", sub);
    else      snprintf(lbl, sizeof lbl, "_443._tcp");
    for (int i = 0; i < z->n; i++)
        if (z->recs[i].type == DNS_TLSA && strcasecmp(z->recs[i].label, lbl) == 0)
            return 1;
    return 0;
}

/* Modern DNS-flag-day default: cap our UDP answers at 1232 bytes even when the
 * client advertises more, to dodge IP fragmentation. Anything larger sets TC and
 * the client retries over TCP. */
#define DNS_MAX_UDP 1232

/* begin a response and immediately clamp it to the answer budget (below the OPT
 * reservation, if any) — one call so every rcode branch gets the same limit. */
static void resp_start(dns_resp *r, uint8_t *out, size_t cap, size_t limit,
                       const dns_query *q, int rcode) {
    dns_resp_begin(r, out, cap, q, rcode);
    dns_resp_set_limit(r, limit);
}

/* Build the full response for `q` into out[cap]. `over_tcp` lifts the 512/EDNS
 * UDP budget to the whole buffer (TCP has no such limit). Returns the response
 * length (a well-formed query always yields at least a header+question). */
size_t dnsd_core_answer(DnsdCore *dc, const dns_query *q,
                        uint8_t *out, size_t cap, int over_tcp) {
    dns_resp r;
    size_t budget;
    if (over_tcp)      budget = cap;
    else if (q->edns)  budget = q->udp_payload < 512 ? 512
                              : q->udp_payload > DNS_MAX_UDP ? DNS_MAX_UDP
                              : q->udp_payload;
    else               budget = 512;
    if (budget > cap) budget = cap;
    size_t limit = budget - (q->edns ? 11u : 0u);   /* reserve the echoed OPT */

    if (q->qclass != DNS_CLASS_IN) { resp_start(&r, out, cap, limit, q, DNS_RCODE_REFUSED); goto done; }
    size_t ql = strlen(q->qname), sl = strlen(dc->suffix);
    if (ql <= sl + 1 || q->qname[ql - sl - 1] != '.' || strcasecmp(q->qname + ql - sl, dc->suffix) != 0) {
        resp_start(&r, out, cap, limit, q, DNS_RCODE_REFUSED); goto done;
    }
    char left[256]; size_t leftlen = ql - sl - 1;
    memcpy(left, q->qname, leftlen); left[leftlen] = '\0';
    char apex[64], sub[192];
    split_apex(left, apex, sizeof apex, sub, sizeof sub);

    /* Apex must be a §3.1 pepenet name (DNS label). Subdomain labels are free
     * form (e.g. _443._tcp) and are matched later against the zone. */
    if (!sp_name_valid(apex, strlen(apex))) {
        resp_start(&r, out, cap, limit, q, DNS_RCODE_NXDOMAIN); goto done;
    }

    uint8_t owner[20];
    int owned = dc->oracle.owner_now(dc->oracle.u, apex, owner);
    if (dc->verbose)
        fprintf(stderr, "query %s → apex=%s sub=%s owned=%d edns=%d tcp=%d\n",
                q->qname, apex, sub[0] ? sub : "@", owned, q->edns, over_tcp);
    if (!owned) { resp_start(&r, out, cap, limit, q, DNS_RCODE_NXDOMAIN); goto done; }

    zone z; dns_state_zone(dc->st, apex, &z);
    resp_start(&r, out, cap, limit, q, DNS_RCODE_NOERROR);

    /* TLS interception: for an A (or ANY) query on a DANE-enabled name, answer
     * the proxy's loopback IP instead of the real origin A. The browser then
     * hits the local proxy, which DANE-verifies the true origin (read straight
     * from the store) before relaying. Names without a _443._tcp TLSA are
     * untouched, so plain A lookups still resolve normally. */
    int redirect_a = dc->tls_redirect && (q->qtype == DNS_A || q->qtype == 255)
                     && has_443_tlsa(&z, sub);

    int label_seen = 0, cname = 0;
    for (int i = 0; i < z.n; i++) {
        zone_rec *rec = &z.recs[i];
        if (strcasecmp(rec->label, sub) != 0) continue;
        label_seen = 1;
        if (redirect_a && rec->type == DNS_A) continue;   /* replaced below */
        if (q->qtype == 255 || rec->type == q->qtype)
            dns_resp_add(&r, q->qname, rec->type, rec->ttl, rec->rdata, rec->rdlen);
    }
    if (redirect_a)
        dns_resp_add(&r, q->qname, DNS_A, 60, dc->tls_redirect_ip, 4);
    if (r.ancount == 0)
        for (int i = 0; i < z.n; i++) {
            zone_rec *rec = &z.recs[i];
            if (strcasecmp(rec->label, sub) == 0 && rec->type == DNS_CNAME) {
                dns_resp_add(&r, q->qname, DNS_CNAME, rec->ttl, rec->rdata, rec->rdlen); cname = 1; break;
            }
        }
    if (r.ancount == 0 && !label_seen && !cname)
        resp_start(&r, out, cap, limit, q, DNS_RCODE_NXDOMAIN);

done:;
    if (q->edns) dns_resp_add_opt(&r, DNS_MAX_UDP);   /* signal we speak EDNS0 */
    return dns_resp_finish(&r);
}

/* ── transports ──────────────────────────────────────────────────────────────── */
static void serve_udp(DnsdCore *dc) {
    uint8_t buf[4096];
    struct sockaddr_storage cli; socklen_t cl = sizeof cli;
    ssize_t n = recvfrom(dc->ufd, buf, sizeof buf, 0, (struct sockaddr *)&cli, &cl);
    if (n < 0) return;
    dns_query q;
    if (dns_parse_query(buf, (size_t)n, &q) != 0) return;
    uint8_t out[4096];
    size_t rn = dnsd_core_answer(dc, &q, out, sizeof out, 0);
    if (rn) sendto(dc->ufd, out, rn, 0, (struct sockaddr *)&cli, cl);
}

static int io_full(int fd, uint8_t *p, size_t n, int writing) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = writing ? write(fd, p + done, n - done)
                            : read(fd, p + done, n - done);
        if (r == 0) return -1;                              /* EOF */
        if (r < 0) { if (errno == EINTR) continue; return -1; }  /* timeout/error */
        done += (size_t)r;
    }
    return 0;
}

/* One TCP client: length-prefixed messages (RFC 7766), served until EOF/timeout.
 * Handled inline on the caller's thread — fine for a low-volume authoritative
 * mirror; a short recv timeout keeps a stalled peer from wedging the UDP path. */
static void serve_tcp(DnsdCore *dc) {
    int c = accept(dc->tfd, NULL, NULL);
    if (c < 0) return;
    struct timeval tv = { 3, 0 };
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    for (;;) {
        uint8_t lenb[2];
        if (io_full(c, lenb, 2, 0) != 0) break;
        size_t mlen = ((size_t)lenb[0] << 8) | lenb[1];
        if (mlen == 0 || mlen > 65535) break;
        static uint8_t req[65536], out[65536];
        if (io_full(c, req, mlen, 0) != 0) break;
        dns_query q;
        if (dns_parse_query(req, mlen, &q) != 0) break;
        size_t rn = dnsd_core_answer(dc, &q, out, sizeof out, 1);
        if (rn == 0) break;
        uint8_t olen[2] = { (uint8_t)(rn >> 8), (uint8_t)rn };
        if (io_full(c, olen, 2, 1) != 0 || io_full(c, out, rn, 1) != 0) break;
    }
    close(c);
}

/* ── lifecycle ───────────────────────────────────────────────────────────────── */
int dnsd_core_bind(DnsdCore *dc, const char *addr, int port) {
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port);
    /* A malformed address must NOT fall through to the memset's 0.0.0.0: that
     * would silently turn an intended loopback bind into a wildcard one and
     * expose the resolver to the whole network. */
    if (inet_pton(AF_INET, addr ? addr : "", &sa.sin_addr) != 1) {
        fprintf(stderr, "dnsd: bad bind address '%s'\n", addr ? addr : "(null)");
        dc->ufd = dc->tfd = -1; return -1;
    }
    int one = 1;

    dc->ufd = socket(AF_INET, SOCK_DGRAM, 0);
    if (dc->ufd < 0) { perror("socket dns/udp"); dc->tfd = -1; return -1; }
    setsockopt(dc->ufd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(dc->ufd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        perror("bind dns/udp"); close(dc->ufd); dc->ufd = -1; dc->tfd = -1; return -1;
    }

    dc->tfd = socket(AF_INET, SOCK_STREAM, 0);
    if (dc->tfd < 0) { perror("socket dns/tcp"); return 0; }   /* UDP-only fallback */
    setsockopt(dc->tfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(dc->tfd, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(dc->tfd, 16) < 0) {
        perror("bind dns/tcp"); close(dc->tfd); dc->tfd = -1;   /* UDP-only fallback */
    }
    return 0;
}

int dnsd_core_poll(DnsdCore *dc, int timeout_ms) {
    if (dc->ufd < 0) return 0;
    struct pollfd pfd[2] = { { dc->ufd, POLLIN, 0 }, { dc->tfd, POLLIN, 0 } };
    int nf = dc->tfd >= 0 ? 2 : 1;
    if (poll(pfd, nf, timeout_ms) <= 0) return 0;
    int served = 0;
    if (pfd[0].revents & POLLIN) { serve_udp(dc); served++; }
    if (dc->tfd >= 0 && (pfd[1].revents & POLLIN)) { serve_tcp(dc); served++; }
    return served;
}

void dnsd_core_close(DnsdCore *dc) {
    if (dc->ufd >= 0) close(dc->ufd);
    if (dc->tfd >= 0) close(dc->tfd);
    dc->ufd = dc->tfd = -1;
}

/* dnsd_core.h — the resolver, extracted for embedding (meld §2/§3).
 *
 * Everything dnsd's main thread did between poll() wakeups, behind a context
 * struct instead of file-scope globals: UDP + TCP DNS on one addr/port,
 * EDNS0 (cap 1232) + TC/TCP fallback, per-query ownership gating, the
 * --tls-redirect DANE steering. dnsd drives it from its CLI loop; a GUI host
 * (pepenet-desktop) drives the same core from its own resolver thread.
 *
 * Threading: the caller owns st/oracle and must call bind/poll/close from ONE
 * thread (the handles are plain sqlite connections — WAL makes them safe
 * alongside the net thread's write handles, not across the caller's threads). */
#ifndef DNSD_CORE_H
#define DNSD_CORE_H

#include "dns_state.h"
#include "zone.h"
#include "dns_wire.h"

#include <stdint.h>
#include <stddef.h>

typedef struct {
    /* caller-owned read handles (open your own connections; WAL-safe) */
    SpState      *st;               /* the record store */
    SpChainOracle oracle;           /* ownership (lease-gated), e.g. dns_chain */
    const char *suffix;             /* hostchain TLD, no dot ("pepe") */
    int         tls_redirect;       /* answer A=<ip> for DANE names */
    uint8_t     tls_redirect_ip[4];
    int         verbose;
    /* sockets (dnsd_core_bind) */
    int         ufd, tfd;           /* -1 when unbound / tcp unavailable */
} DnsdCore;

/* Bind UDP + TCP on addr:port. TCP failure is tolerated (UDP-only, tfd = -1);
 * UDP failure is not. Returns 0 ok, -1 on error. */
int  dnsd_core_bind(DnsdCore *dc, const char *addr, int port);

/* One poll iteration: wait ≤ timeout_ms, service one UDP datagram and/or one
 * TCP client. Returns the number of transports serviced (0 on timeout). */
int  dnsd_core_poll(DnsdCore *dc, int timeout_ms);

void dnsd_core_close(DnsdCore *dc);

/* The answer builder itself, for tests and in-process resolution: build the
 * full response for `q` into out[cap]; over_tcp lifts the UDP budget. */
size_t dnsd_core_answer(DnsdCore *dc, const dns_query *q,
                        uint8_t *out, size_t cap, int over_tcp);

#endif

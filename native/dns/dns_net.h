/* dns_net.h — zone gossip over the chain-wire mesh (dn* commands).
 *
 * The sync unit is the NAME: a zone is ≤ DNS_BUDGET bytes of held ops, so a
 * full zone rides one frame. Three messages (payloads after the dn command):
 *
 *   dnzinv : var count ‖ [ nlen:u8 name ‖ digest32 ]*        (i hold this)
 *   dnzget : nlen:u8 name                                    (send me yours)
 *   dnzdat : nlen:u8 name ‖ var count ‖ [ oplen:var op ]*    (full dump;
 *            the clear op first when held, then rows in key order)
 *
 * Convergence: a peer whose digest differs pulls; after admitting a dump we
 * re-announce the name to everyone INCLUDING the source (if we held ops the
 * source lacked, its digest now mismatches ours and it pulls back). Ops that
 * anchor ahead of our sync (-2) sit in a small hold queue and retry on the
 * tick. Everything rides the IdxMeshHooks surface dnsd/desktop already own;
 * this module is single-instance (one store per process). */
#ifndef DNS_NET_H
#define DNS_NET_H

#include <stdint.h>
#include <stddef.h>
#include "dns_state.h"

typedef void (*dnsnet_send_fn)(void *peer, const char *cmd, const uint8_t *pay, size_t n);

/* Bind the module to its store + oracle (call once, before any peer). */
void  dnsnet_init(SpState *st, SpChainOracle oracle, int verbose);

/* Peer lifecycle — mirror of IdxMeshHooks up/msg/down/tick. */
void *dnsnet_up(void *peer, dnsnet_send_fn send);      /* → handle (NULL = full) */
void  dnsnet_msg(void *handle, const char *cmd, const uint8_t *pay, int n);
void  dnsnet_down(void *handle);
void  dnsnet_tick(void);                               /* hold-queue + anti-entropy */

/* A local publish changed `name` — announce it to every live peer. */
void  dnsnet_announce(const char *name);

/* live peer count (status surfaces) */
int   dnsnet_peers(void);

#endif /* DNS_NET_H */

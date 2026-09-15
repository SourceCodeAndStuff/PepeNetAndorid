// pn_core.h — the headless PepeNet node: chain sync + .pepe resolver + DANE proxy.
// Same three engines pepenet-web (Windows service) embeds; no wallet, no GUI.
#ifndef PN_CORE_H
#define PN_CORE_H
#include <stddef.h>

// home: absolute data dir (chain db, zone store, CA). 1 = all engines up.
int  pn_core_start(const char *home);
void pn_core_stop(void);
int  pn_core_running(void);
// one-line human status ("height 1234 · 3 peers · 12 zones · proxy ok")
void pn_core_status(char *out, size_t cap);
// absolute path of the name-constrained root CA certificate (PEM)
const char *pn_core_ca_path(void);
// The Discover directory (every .pepe name with a zone) as a JSON array:
// [{"name","registered","lease_expiry","has_a","has_tlsa","a","site","nrec"}].
// Returns bytes written (0 = not running / no room).
size_t pn_core_directory_json(char *out, size_t cap);
#endif

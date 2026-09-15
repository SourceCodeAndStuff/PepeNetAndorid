// pn_core.c — boot/stop/status for the embedded engines (mirrors
// pepenet-desktop src/web_svc.c boot_engines, minus the Windows service).
#include "pn_core.h"
#include "appconf.h"
#include "platform.h"
#include "engine.h"
#include "dnsnet.h"
#include "webproxy.h"
#include "ca.h"
#include "wallet.h"
#include "dirscan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const char *idx_sync_agent;

DeskWallet WLT;                 // zeroed: headless node has no wallet

static int g_up;

int pn_core_start(const char *home) {
    if (g_up) return 1;
    if (home && home[0]) {
        setenv("PEPENET_HOME", home, 1);
        setenv("HOME", home, 1);
    }
    char db[600], ddir[512];
    platform_data_path(APP_COIN ".db", db, sizeof db);
    ca_set_dir(platform_data_dir(ddir, sizeof ddir));
    idx_sync_agent = APP_CHAIN_AGENT;
    dnsnet_boot(APP_COIN, db);
    if (!dnsnet_start()) {
        fprintf(stderr, "pn_core: dnsnet_start failed\n");
        return 0;
    }
    if (!webproxy_start(dnsnet_store_path(), dnsnet_chain_path())) {
        fprintf(stderr, "pn_core: webproxy_start failed\n");
        dnsnet_stop();
        return 0;
    }
    if (!engine_start(APP_COIN, db, APP_SEED_PEER)) {
        fprintf(stderr, "pn_core: engine_start failed\n");
        webproxy_stop();
        dnsnet_stop();
        return 0;
    }
    dirscan_start(dnsnet_store_path(), dnsnet_chain_path());
    g_up = 1;
    fprintf(stderr, "pn_core: resolver 127.0.0.1:%d  proxy 127.0.0.1:%d  db %s  ca %s\n",
            APP_DNS_PORT, APP_PROXY_PORT, db, ca_root_cert_path());
    return 1;
}

void pn_core_stop(void) {
    if (!g_up) return;
    dirscan_stop();
    webproxy_stop();
    dnsnet_stop();
    engine_stop();
    g_up = 0;
}

int pn_core_running(void) { return g_up; }

void pn_core_status(char *out, size_t cap) {
    if (!g_up) { snprintf(out, cap, "stopped"); return; }
    EngineStatus es; DnsStatus ds; WebStatus ws;
    memset(&es, 0, sizeof es); memset(&ds, 0, sizeof ds); memset(&ws, 0, sizeof ws);
    engine_status(&es);
    dnsnet_status(&ds);
    webproxy_status(&ws);
    const char *sync;
    char sb[80];
    if (es.peer_height > 0 && es.height < es.peer_height) {
        snprintf(sb, sizeof sb, "syncing %lld/%lld", (long long)es.height,
                 (long long)es.peer_height);
        sync = sb;
    } else if (es.height > 0) {
        snprintf(sb, sizeof sb, "block %lld", (long long)es.height);
        sync = sb;
    } else {
        sync = "connecting";
    }
    snprintf(out, cap, "%s | %d mesh peers | %lld sites | %s | TLS %lld ok / %lld fail",
             sync, ds.peers, (long long)ds.zones_held, ds.phase,
             (long long)ws.dane_ok, (long long)ws.dane_fail);
}

const char *pn_core_ca_path(void) { return ca_root_cert_path(); }

static size_t json_str(char *o, size_t cap, const char *s) {
    size_t n = 0;
    #define PUT(c) do { if (n + 1 < cap) o[n] = (c); n++; } while (0)
    PUT('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') { PUT('\\'); PUT((char)*p); }
        else if (*p < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", *p); for (char *q = b; *q; q++) PUT(*q); }
        else PUT((char)*p);
    }
    PUT('"');
    #undef PUT
    return n;
}

size_t pn_core_directory_json(char *out, size_t cap) {
    if (!g_up || cap < 3) return 0;
    DirRow *rows = calloc(DIR_MAX, sizeof *rows);
    if (!rows) return 0;
    int n = dirscan_snapshot(rows, DIR_MAX, NULL, NULL);
    size_t o = 0;
    out[o++] = '[';
    for (int i = 0; i < n; i++) {
        DirRow *r = &rows[i];
        r->name[sizeof r->name - 1] = 0; r->site[sizeof r->site - 1] = 0; r->a_ip[sizeof r->a_ip - 1] = 0;
        char head[160];
        int hn = snprintf(head, sizeof head,
            "%s{\"registered\":%d,\"lease_expiry\":%lld,\"has_a\":%d,\"has_tlsa\":%d,\"nrec\":%d,\"name\":",
            i ? "," : "", r->registered, (long long)r->lease_expiry, r->has_a, r->has_tlsa, r->nrec);
        // worst case per row: head + 3 escaped strings (6x) + keys
        if (o + (size_t)hn + 6 * (sizeof r->name + sizeof r->site + sizeof r->a_ip) + 32 >= cap) break;
        memcpy(out + o, head, (size_t)hn); o += (size_t)hn;
        o += json_str(out + o, cap - o, r->name);
        memcpy(out + o, ",\"a\":", 5); o += 5;
        o += json_str(out + o, cap - o, r->a_ip);
        memcpy(out + o, ",\"site\":", 8); o += 8;
        o += json_str(out + o, cap - o, r->site);
        out[o++] = '}';
    }
    out[o++] = ']';
    out[o] = 0;
    free(rows);
    return o;
}

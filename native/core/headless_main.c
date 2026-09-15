// headless_main.c — desktop test harness for pn_core (not built for Android).
#include "pn_core.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile sig_atomic_t run = 1;
static void on_sig(int s) { (void)s; run = 0; }

int main(int argc, char **argv) {
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    if (!pn_core_start(argc > 1 ? argv[1] : NULL)) return 1;
    while (run) {
        char st[256];
        pn_core_status(st, sizeof st);
        fprintf(stderr, "%s\n", st);
        for (int i = 0; i < 10 && run; i++) sleep(1);
    }
    pn_core_stop();
    return 0;
}

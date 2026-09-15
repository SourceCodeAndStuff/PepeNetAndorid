#define _GNU_SOURCE
// platform_min.c — the two platform.h primitives the headless engines use
// (data dir + data path). Android sets PEPENET_HOME to the app's files dir
// before booting the engines; desktop Linux falls back to ~/.pepenet.
#include "platform.h"
#include "appconf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

const char *platform_data_dir(char *out, size_t cap) {
    const char *h = getenv("PEPENET_HOME");
    if (h && h[0] == '/') {
        snprintf(out, cap, "%s", h);
    } else {
        const char *home = getenv("HOME");
        snprintf(out, cap, "%s/." APP_DATA_DIR, (home && home[0]) ? home : ".");
    }
    mkdir(out, 0700);
    return out;
}

const char *platform_data_path(const char *name, char *out, size_t cap) {
    char dir[512];
    platform_data_dir(dir, sizeof dir);
    snprintf(out, cap, "%s/%s", dir, name);
    return out;
}

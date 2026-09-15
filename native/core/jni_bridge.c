// jni_bridge.c — Kotlin ↔ pn_core. Kotlin side: com.example.pepenet.core.PepeCore
//
// The C engines log to stderr; on Android that goes nowhere, so a pipe thread
// forwards every line to logcat (tag "PepeNetCore") and keeps the last lines in
// a ring the UI can show.
#include "pn_core.h"

#include <android/log.h>
#include <jni.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "PepeNetCore"
#define RING_LINES 40
#define LINE_MAX_ 200

static char g_ring[RING_LINES][LINE_MAX_];
static int g_ring_head, g_ring_count;
static pthread_mutex_t g_ring_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_log_started;

static void ring_push(const char *s) {
    pthread_mutex_lock(&g_ring_mu);
    snprintf(g_ring[g_ring_head], LINE_MAX_, "%s", s);
    // NewStringUTF needs modified UTF-8 and lines may be cut mid-glyph:
    // keep the UI copy plain ASCII (logcat gets the original bytes)
    for (char *c = g_ring[g_ring_head]; *c; c++)
        if ((unsigned char)*c >= 0x80) *c = '?';
    g_ring_head = (g_ring_head + 1) % RING_LINES;
    if (g_ring_count < RING_LINES) g_ring_count++;
    pthread_mutex_unlock(&g_ring_mu);
}

static void *log_pump(void *arg) {
    int fd = (int)(intptr_t)arg;
    char buf[1024], line[LINE_MAX_];
    size_t ll = 0;
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            char c = buf[i];
            if (c == '\n' || ll == sizeof line - 1) {
                line[ll] = 0;
                if (ll) {
                    __android_log_write(ANDROID_LOG_INFO, TAG, line);
                    ring_push(line);
                }
                ll = 0;
                if (c != '\n') line[ll++] = c;
            } else {
                line[ll++] = c;
            }
        }
    }
    return NULL;
}

static void start_log_pump(void) {
    if (g_log_started) return;
    int p[2];
    if (pipe(p) != 0) return;
    setvbuf(stderr, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);
    dup2(p[1], STDERR_FILENO);
    dup2(p[1], STDOUT_FILENO);
    close(p[1]);
    pthread_t t;
    if (pthread_create(&t, NULL, log_pump, (void *)(intptr_t)p[0]) == 0) {
        pthread_detach(t);
        g_log_started = 1;
    }
}

#define JFN(ret, name) JNIEXPORT ret JNICALL Java_com_example_pepenet_core_PepeCore_##name

JFN(jboolean, nativeStart)(JNIEnv *env, jobject self, jstring jhome) {
    (void)self;
    signal(SIGPIPE, SIG_IGN);   // a browser closing a tunnel must not kill us
    start_log_pump();
    const char *home = (*env)->GetStringUTFChars(env, jhome, NULL);
    int ok = pn_core_start(home);
    (*env)->ReleaseStringUTFChars(env, jhome, home);
    return ok ? JNI_TRUE : JNI_FALSE;
}

JFN(void, nativeStop)(JNIEnv *env, jobject self) {
    (void)env; (void)self;
    pn_core_stop();
}

JFN(jboolean, nativeRunning)(JNIEnv *env, jobject self) {
    (void)env; (void)self;
    return pn_core_running() ? JNI_TRUE : JNI_FALSE;
}

JFN(jstring, nativeStatus)(JNIEnv *env, jobject self) {
    (void)self;
    char st[400];
    pn_core_status(st, sizeof st);
    return (*env)->NewStringUTF(env, st);
}

JFN(jstring, nativeCaPath)(JNIEnv *env, jobject self) {
    (void)self;
    const char *p = pn_core_ca_path();
    return (*env)->NewStringUTF(env, p ? p : "");
}

JFN(jstring, nativeRecentLog)(JNIEnv *env, jobject self) {
    (void)self;
    char out[RING_LINES * LINE_MAX_];
    size_t o = 0;
    out[0] = 0;
    pthread_mutex_lock(&g_ring_mu);
    int start = (g_ring_head - g_ring_count + RING_LINES) % RING_LINES;
    for (int i = 0; i < g_ring_count; i++) {
        const char *l = g_ring[(start + i) % RING_LINES];
        int w = snprintf(out + o, sizeof out - o, "%s\n", l);
        if (w < 0 || (size_t)w >= sizeof out - o) break;
        o += (size_t)w;
    }
    pthread_mutex_unlock(&g_ring_mu);
    // NewStringUTF wants modified UTF-8; engine logs are ASCII + a few UTF-8
    // glyphs, fine for display
    return (*env)->NewStringUTF(env, out);
}

JFN(jbyteArray, nativeDirectoryJson)(JNIEnv *env, jobject self) {
    (void)self;
    size_t cap = 512 * 1024;
    char *buf = malloc(cap);
    size_t n = buf ? pn_core_directory_json(buf, cap) : 0;
    if (n == 0) { if (buf) { buf[0] = '['; buf[1] = ']'; } n = 2; }
    // raw UTF-8 bytes: owner-written _site text may hold any Unicode
    jbyteArray arr = (*env)->NewByteArray(env, (jsize)n);
    if (arr && buf) (*env)->SetByteArrayRegion(env, arr, 0, (jsize)n, (const jbyte *)buf);
    free(buf);
    return arr;
}

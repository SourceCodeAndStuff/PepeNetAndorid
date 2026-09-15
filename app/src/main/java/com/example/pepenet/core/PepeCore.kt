package com.example.pepenet.core

/**
 * JNI facade over the native PepeNet node (native/core/jni_bridge.c).
 *
 * The node is the canonical PepeNet C stack — Pepecoin chain sync + namespace
 * fold, the .pepe zone mesh and resolver (127.0.0.1:15353), and the DANE TLS
 * proxy (127.0.0.1:8443, with its CONNECT front door on 127.0.0.1:8444).
 */
object PepeCore {
    const val DNS_PORT = 15353
    const val TLS_PROXY_PORT = 8443
    const val CONNECT_PORT = 8444

    init {
        System.loadLibrary("pepenet_core")
    }

    /** Boots all engines with [home] as the data dir. Safe to call twice. */
    fun start(home: String): Boolean = nativeStart(home)
    fun stop() = nativeStop()
    fun isRunning(): Boolean = nativeRunning()
    fun status(): String = nativeStatus()
    /** PEM path of the name-constrained ".pepe only" root CA. */
    fun caCertPath(): String = nativeCaPath()
    fun recentLog(): String = nativeRecentLog()
    /** Discover directory snapshot (JSON array, see pn_core.h). */
    fun directoryJson(): String = String(nativeDirectoryJson(), Charsets.UTF_8)

    private external fun nativeStart(home: String): Boolean
    private external fun nativeStop()
    private external fun nativeRunning(): Boolean
    private external fun nativeStatus(): String
    private external fun nativeCaPath(): String
    private external fun nativeRecentLog(): String
    private external fun nativeDirectoryJson(): ByteArray
}

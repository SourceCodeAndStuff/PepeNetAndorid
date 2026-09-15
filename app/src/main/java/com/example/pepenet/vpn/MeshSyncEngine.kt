package com.example.pepenet.vpn

import android.content.Context
import com.example.pepenet.core.PepeCore
import java.io.File

/**
 * Owns the native PepeNet node (chain sync + zone mesh + resolver + DANE proxy).
 * Runs inside the VPN service process (":vpn"), which is killed on disconnect
 * so every connect starts the C engines from a clean slate.
 */
object MeshSyncEngine {

    fun dataDir(context: Context): File =
        File(context.filesDir, "pepenet").apply { mkdirs() }

    fun start(context: Context): Boolean = PepeCore.start(dataDir(context).absolutePath)

    fun stop() {
        if (PepeCore.isRunning()) PepeCore.stop()
    }

    fun status(): String = if (PepeCore.isRunning()) PepeCore.status() else "stopped"

    fun recentLog(): String = PepeCore.recentLog()

    /** Where the service drops the directory for the UI process to read. */
    fun directoryFile(context: Context): File = File(dataDir(context), "directory.json")

    /** Snapshot the Discover directory to [directoryFile] (atomic rename). */
    fun writeDirectory(context: Context) {
        if (!PepeCore.isRunning()) return
        val json = PepeCore.directoryJson()
        val target = directoryFile(context)
        val tmp = File(target.parentFile, "directory.json.tmp")
        tmp.writeText(json, Charsets.UTF_8)
        if (!tmp.renameTo(target)) {
            target.delete()
            tmp.renameTo(target)
        }
    }
}

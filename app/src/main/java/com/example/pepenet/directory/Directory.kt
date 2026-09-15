package com.example.pepenet.directory

import android.content.Context
import com.example.pepenet.vpn.MeshSyncEngine
import org.json.JSONArray

/** One .pepe name from the chain-backed directory (native dirscan). */
data class Site(
    val name: String,              // apex, without ".pepe"
    val registered: Boolean,       // owned on chain right now
    val leaseExpiry: Long,
    val hasWebsite: Boolean,       // zone has an apex A record
    val hasTlsa: Boolean,          // _443._tcp TLSA → DANE-pinned HTTPS
    val address: String,
    val siteText: String,          // owner's `_site` TXT record
    val records: Int,
) {
    val host: String get() = "$name.pepe"
}

object Directory {
    fun load(context: Context): List<Site> {
        val f = MeshSyncEngine.directoryFile(context)
        if (!f.isFile) return emptyList()
        return try {
            val arr = JSONArray(f.readText(Charsets.UTF_8))
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                Site(
                    name = o.optString("name"),
                    registered = o.optInt("registered") != 0,
                    leaseExpiry = o.optLong("lease_expiry"),
                    hasWebsite = o.optInt("has_a") != 0,
                    hasTlsa = o.optInt("has_tlsa") != 0,
                    address = o.optString("a"),
                    siteText = o.optString("site"),
                    records = o.optInt("nrec"),
                )
            }.filter { it.name.isNotEmpty() }
        } catch (e: Exception) {
            emptyList()
        }
    }
}

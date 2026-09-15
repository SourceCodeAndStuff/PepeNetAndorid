package com.example.pepenet.directory

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext

class DirectoryViewModel(app: Application) : AndroidViewModel(app) {

    private val _sites = MutableStateFlow<List<Site>>(emptyList())
    val sites: StateFlow<List<Site>> = _sites.asStateFlow()

    private val _probes = MutableStateFlow<Map<String, SiteProbe>>(emptyMap())
    val probes: StateFlow<Map<String, SiteProbe>> = _probes.asStateFlow()

    private val _query = MutableStateFlow("")
    val query: StateFlow<String> = _query.asStateFlow()

    private val lastProbe = HashMap<String, Long>()
    private val inFlight: MutableSet<String> = java.util.concurrent.ConcurrentHashMap.newKeySet()
    private val permits = Semaphore(4)
    private var loop: Job? = null

    fun setQuery(q: String) { _query.value = q }

    /** Poll the directory + probe sites while the list is on screen. */
    fun setActive(active: Boolean) {
        if (!active) { loop?.cancel(); loop = null; return }
        if (loop?.isActive == true) return
        loop = viewModelScope.launch {
            while (isActive) {
                val list = withContext(Dispatchers.IO) { Directory.load(getApplication()) }
                _sites.value = list
                scheduleProbes(list)
                delay(10_000)
            }
        }
    }

    fun reprobe(site: Site) {
        lastProbe.remove(site.name)
        scheduleProbes(listOf(site))
    }

    private fun scheduleProbes(list: List<Site>) {
        val now = System.currentTimeMillis()
        for (site in list) {
            val key = site.name
            val last = lastProbe[key]
            val state = _probes.value[key]?.status
            val maxAge = if (state == SiteStatus.ONLINE) 5 * 60_000L else 2 * 60_000L
            if (last != null && now - last < maxAge) continue
            if (!inFlight.add(key)) continue
            lastProbe[key] = now
            if (state == null) _probes.update { it + (key to SiteProbe(SiteStatus.CHECKING)) }
            viewModelScope.launch(Dispatchers.IO) {
                val result = permits.withPermit { SiteProber.probe(getApplication(), site) }
                // keep a previously fetched icon if this round had none
                val merged = if (result.icon == null) result.copy(icon = _probes.value[key]?.icon) else result
                _probes.update { it + (key to merged) }
                inFlight.remove(key)
            }
        }
    }
}

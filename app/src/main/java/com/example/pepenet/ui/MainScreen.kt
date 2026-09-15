package com.example.pepenet.ui

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.pepenet.directory.Site
import com.example.pepenet.directory.SiteProbe
import com.example.pepenet.directory.SiteStatus
import java.util.Locale

@Composable
fun MainScreen(
    state: UiState,
    sites: List<Site>,
    probes: Map<String, SiteProbe>,
    query: String,
    onQueryChange: (String) -> Unit,
    onToggle: () -> Unit,
    onInstallCa: () -> Unit,
    onDismissCaGuide: () -> Unit,
    onOpenSite: (Site) -> Unit,
    onDismissMessage: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showLog by remember { mutableStateOf(false) }
    val colors = MaterialTheme.colorScheme
    val running = state.conn == ConnState.RUNNING
    val directoryUnlocked = running && state.caInstalled

    if (state.showCaGuide && state.caReady && !state.caInstalled) {
        AlertDialog(
            onDismissRequest = onDismissCaGuide,
            title = { Text("Finish setup: trust .pepe") },
            text = { CaSteps(state.caSteps) },
            confirmButton = {
                TextButton(onClick = { onDismissCaGuide(); onInstallCa() }) { Text("Install certificate") }
            },
            dismissButton = { TextButton(onClick = onDismissCaGuide) { Text("Later") } },
        )
    }

    val q = query.trim().lowercase(Locale.ROOT).removeSuffix(".pepe")
    val filtered = if (q.isEmpty()) sites else sites.filter {
        it.name.lowercase(Locale.ROOT).contains(q) || it.siteText.lowercase(Locale.ROOT).contains(q)
    }
    // online sites first, then websites, then bare names
    val ordered = filtered.sortedWith(
        compareBy<Site>(
            { rank(probes[it.name]?.status, it) },
            { it.name },
        )
    )

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.weight(1f)) {
                    Text("PepeNet", fontSize = 28.sp, fontWeight = FontWeight.Bold, color = colors.primary)
                    Text(
                        when (state.conn) {
                            ConnState.RUNNING -> "Connected"
                            ConnState.STARTING -> "Connecting…"
                            ConnState.ERROR -> "Problem"
                            ConnState.STOPPED -> "Not connected"
                        },
                        color = when (state.conn) {
                            ConnState.RUNNING -> colors.secondary
                            ConnState.ERROR -> colors.error
                            else -> colors.onSurfaceVariant
                        },
                        fontSize = 13.sp,
                    )
                }
                val starting = state.conn == ConnState.STARTING
                Button(
                    onClick = onToggle,
                    enabled = !starting,
                    shape = RoundedCornerShape(24.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (running || state.conn == ConnState.ERROR) colors.error else colors.primary,
                    ),
                ) {
                    if (starting) {
                        CircularProgressIndicator(Modifier.size(18.dp), color = colors.onPrimary, strokeWidth = 2.dp)
                    } else {
                        Text(if (running || state.conn == ConnState.ERROR) "Disconnect" else "Connect")
                    }
                }
            }
        }

        if (state.detail.isNotBlank()) {
            item { Text(state.detail, fontSize = 12.sp, color = colors.onSurfaceVariant) }
        }

        state.message?.let { msg ->
            item {
                Card(colors = CardDefaults.cardColors(containerColor = colors.surfaceVariant), modifier = Modifier.fillMaxWidth()) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(msg, modifier = Modifier.weight(1f), fontSize = 13.sp)
                        TextButton(onClick = onDismissMessage) { Text("OK") }
                    }
                }
            }
        }

        if (!directoryUnlocked) {
            item { SetupCard(state, onInstallCa) }
        } else {
            item {
                OutlinedTextField(
                    value = query,
                    onValueChange = onQueryChange,
                    singleLine = true,
                    placeholder = { Text("Search .pepe domains") },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            item {
                val online = sites.count { probes[it.name]?.status == SiteStatus.ONLINE }
                Text(
                    if (sites.isEmpty()) "Waiting for the directory — names appear as the node syncs."
                    else "${filtered.size} of ${sites.size} domains · $online online",
                    fontSize = 12.sp, color = colors.onSurfaceVariant,
                )
            }
            items(ordered, key = { it.name }) { site ->
                SiteRow(site, probes[site.name], onClick = { onOpenSite(site) })
            }
        }

        if (state.log.isNotBlank()) {
            item {
                TextButton(onClick = { showLog = !showLog }) { Text(if (showLog) "Hide node log" else "Show node log") }
            }
            if (showLog) {
                item {
                    Text(
                        state.log, fontFamily = FontFamily.Monospace, fontSize = 10.sp,
                        color = colors.onSurfaceVariant, modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        }
    }
}

private fun rank(status: SiteStatus?, site: Site): Int = when {
    status == SiteStatus.ONLINE -> 0
    site.hasWebsite && (status == null || status == SiteStatus.CHECKING) -> 1
    site.hasWebsite -> 2
    else -> 3
}

@Composable
private fun SetupCard(state: UiState, onInstallCa: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    Card(colors = CardDefaults.cardColors(containerColor = colors.surface), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Browse .pepe", fontWeight = FontWeight.SemiBold)
            when {
                state.conn != ConnState.RUNNING ->
                    Text("Connect to load the directory of .pepe websites.", color = colors.onSurfaceVariant)
                !state.caReady ->
                    Text("Creating your personal .pepe certificate…", color = colors.onSurfaceVariant)
                else -> {
                    if (state.caOutdated) {
                        Text(
                            "An older PepeNet certificate is installed. Install this new one " +
                                "(remove the old one under View security certificates › User).",
                            color = colors.error, fontSize = 13.sp,
                        )
                    } else {
                        Text(
                            "One-time step so Chrome trusts .pepe sites. The certificate only works " +
                                "for .pepe names, never for other websites. The directory unlocks after.",
                            color = colors.onSurfaceVariant,
                        )
                    }
                    CaSteps(state.caSteps)
                    Button(onClick = onInstallCa) { Text("Install certificate") }
                }
            }
        }
    }
}

@Composable
private fun SiteRow(site: Site, probe: SiteProbe?, onClick: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    Card(
        colors = CardDefaults.cardColors(containerColor = colors.surface),
        modifier = Modifier.fillMaxWidth().clickable(enabled = site.hasWebsite, onClick = onClick),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Favicon(site, probe?.icon)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        site.host, fontWeight = FontWeight.SemiBold, maxLines = 1,
                        overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false),
                    )
                    Spacer(Modifier.width(8.dp))
                    StatusChip(probe?.status ?: if (site.hasWebsite) SiteStatus.CHECKING else SiteStatus.NO_WEBSITE)
                }
                Text(
                    site.siteText.ifBlank { if (site.hasWebsite) "No _site description" else "Registered name, no website" },
                    fontSize = 13.sp,
                    color = if (site.siteText.isBlank()) colors.onSurfaceVariant else colors.onSurface,
                    maxLines = 2, overflow = TextOverflow.Ellipsis,
                )
                val meta = buildList {
                    if (site.hasTlsa) add("DANE pinned")
                    if (site.address.isNotBlank()) add(site.address)
                    if (!site.registered) add("lease lapsed")
                    probe?.detail?.takeIf { probe.status != SiteStatus.ONLINE && it.isNotBlank() }?.let { add(it) }
                }.joinToString(" · ")
                if (meta.isNotEmpty()) Text(meta, fontSize = 11.sp, color = colors.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun Favicon(site: Site, icon: Bitmap?) {
    val colors = MaterialTheme.colorScheme
    Box(
        Modifier.size(40.dp).clip(RoundedCornerShape(8.dp)).background(colors.surfaceVariant),
        contentAlignment = Alignment.Center,
    ) {
        if (icon != null) {
            Image(bitmap = icon.asImageBitmap(), contentDescription = null, modifier = Modifier.size(32.dp))
        } else {
            Text(
                site.name.take(1).uppercase(Locale.ROOT),
                fontWeight = FontWeight.Bold, color = colors.primary, fontSize = 18.sp,
            )
        }
    }
}

@Composable
private fun StatusChip(status: SiteStatus) {
    val colors = MaterialTheme.colorScheme
    val (label, tint) = when (status) {
        SiteStatus.ONLINE -> "Online" to colors.secondary
        SiteStatus.CHECKING -> "Checking" to colors.onSurfaceVariant
        SiteStatus.OFFLINE -> "Offline" to colors.error
        SiteStatus.TLS_FAILED -> "Pin mismatch" to colors.error
        SiteStatus.NO_WEBSITE -> "No site" to colors.onSurfaceVariant
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(tint))
        Spacer(Modifier.width(4.dp))
        Text(label, fontSize = 11.sp, color = tint)
    }
}

@Composable
private fun CaSteps(steps: List<String>) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        steps.forEachIndexed { i, step ->
            Text("${i + 1}. $step", fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurface)
        }
    }
}

package com.example.pepenet

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.pepenet.directory.DirectoryViewModel
import com.example.pepenet.ui.ConnState
import com.example.pepenet.ui.MainScreen
import com.example.pepenet.ui.MainViewModel
import com.example.pepenet.ui.theme.PepeNetTheme
import com.example.pepenet.vpn.CertificateManager
import com.example.pepenet.vpn.PepeVpnService

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()
    private val directoryVm: DirectoryViewModel by viewModels()
    private val handler = Handler(Looper.getMainLooper())
    private var lastStatusAt = 0L

    // the :vpn process broadcasts every 2 s; silence means it died
    private val staleCheck = object : Runnable {
        override fun run() {
            val st = viewModel.state.value.conn
            if ((st == ConnState.RUNNING || st == ConnState.ERROR) &&
                SystemClock.elapsedRealtime() - lastStatusAt > 6000
            ) {
                viewModel.onServiceStatus("stopped", "", "")
            }
            handler.postDelayed(this, 2000)
        }
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val before = viewModel.state.value.conn
            viewModel.onServiceStatus(
                intent.getStringExtra(PepeVpnService.EXTRA_STATE) ?: "stopped",
                intent.getStringExtra(PepeVpnService.EXTRA_DETAIL) ?: "",
                intent.getStringExtra(PepeVpnService.EXTRA_LOG) ?: "",
            )
            lastStatusAt = SystemClock.elapsedRealtime()
            if (viewModel.state.value.conn != before) refreshCa()
        }
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) startVpn()
        else viewModel.showMessage("PepeNet needs the VPN permission to route .pepe sites.")
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ -> requestVpnThenStart() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            PepeNetTheme {
                val state by viewModel.state.collectAsStateWithLifecycle()
                val sites by directoryVm.sites.collectAsStateWithLifecycle()
                val probes by directoryVm.probes.collectAsStateWithLifecycle()
                val query by directoryVm.query.collectAsStateWithLifecycle()
                val unlocked = state.conn == ConnState.RUNNING && state.caInstalled
                LaunchedEffect(unlocked) { directoryVm.setActive(unlocked) }
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    MainScreen(
                        state = state,
                        sites = sites,
                        probes = probes,
                        query = query,
                        onQueryChange = directoryVm::setQuery,
                        onToggle = ::onToggle,
                        onInstallCa = ::installCa,
                        onDismissCaGuide = { viewModel.showCaGuide(false) },
                        onOpenSite = { openUrl("https://${it.host}/") },
                        onDismissMessage = { viewModel.showMessage(null) },
                        modifier = Modifier.padding(innerPadding),
                    )
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        ContextCompat.registerReceiver(
            this, statusReceiver, IntentFilter(PepeVpnService.ACTION_STATUS),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        refreshCa()
        lastStatusAt = SystemClock.elapsedRealtime()
        handler.post(staleCheck)
    }

    override fun onStop() {
        handler.removeCallbacks(staleCheck)
        unregisterReceiver(statusReceiver)
        super.onStop()
    }

    private var caPromptedThisSession = false

    private fun refreshCa() {
        val st = CertificateManager.trustState(this)
        val ready = st != CertificateManager.TrustState.NO_CA
        val installed = st == CertificateManager.TrustState.INSTALLED
        viewModel.setCa(ready, installed, st == CertificateManager.TrustState.OUTDATED, CertificateManager.steps())
        // first time the node is up with an untrusted root: walk the user through it
        if (ready && !installed && !caPromptedThisSession &&
            viewModel.state.value.conn == ConnState.RUNNING
        ) {
            caPromptedThisSession = true
            viewModel.showCaGuide(true)
        }
    }

    override fun onResume() {
        super.onResume()
        refreshCa()   // back from Settings: detect the install
    }

    private fun onToggle() {
        when (viewModel.state.value.conn) {
            ConnState.RUNNING, ConnState.ERROR -> {
                startService(Intent(this, PepeVpnService::class.java).setAction(PepeVpnService.ACTION_DISCONNECT))
            }
            ConnState.STOPPED -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                    checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                ) {
                    notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                } else {
                    requestVpnThenStart()
                }
            }
            ConnState.STARTING -> Unit
        }
    }

    private fun requestVpnThenStart() {
        val prepare = VpnService.prepare(this)
        if (prepare != null) vpnPermissionLauncher.launch(prepare) else startVpn()
    }

    private fun startVpn() {
        viewModel.setConnecting()
        val intent = Intent(this, PepeVpnService::class.java).setAction(PepeVpnService.ACTION_CONNECT)
        ContextCompat.startForegroundService(this, intent)
    }

    private fun installCa() {
        val saved = try { CertificateManager.exportToDownloads(this) } catch (e: Exception) { null }
        if (saved == null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            viewModel.showMessage("Couldn't save the certificate — connect first, then try again.")
            return
        }
        for (intent in CertificateManager.installIntents(this)) {
            try {
                startActivity(intent)
                return
            } catch (e: ActivityNotFoundException) {
            } catch (e: SecurityException) {
            }
        }
        viewModel.showMessage("Open Settings and search for \"CA certificate\".")
    }

    private fun openUrl(url: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (e: ActivityNotFoundException) {
            viewModel.showMessage("No browser found. Install Chrome to open .pepe sites.")
        }
    }
}

package com.example.pepenet.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.InetAddresses
import android.net.NetworkCapabilities
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.util.Log
import com.example.pepenet.MainActivity
import com.example.pepenet.R
import java.net.Inet4Address
import java.net.InetAddress

/**
 * Connect = boot the native PepeNet node, then bring up a tiny VPN whose only
 * jobs are (1) hand Android our HTTP proxy, so browsers send .pepe requests to
 * the DANE proxy, and (2) answer DNS so .pepe names resolve for other apps.
 *
 * Runs in its own process (":vpn"); disconnect kills that process so the C
 * engines always restart cleanly. State reaches the UI via [ACTION_STATUS]
 * broadcasts.
 */
class PepeVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.example.pepenet.CONNECT"
        const val ACTION_DISCONNECT = "com.example.pepenet.DISCONNECT"
        const val ACTION_STATUS = "com.example.pepenet.STATUS"
        const val EXTRA_STATE = "state"          // "starting" | "running" | "stopped" | "error"
        const val EXTRA_DETAIL = "detail"
        const val EXTRA_LOG = "log"

        private const val TAG = "PepeVpnService"
        private const val CHANNEL_ID = "pepenet_vpn"
        private const val NOTIFICATION_ID = 1
        private const val STATUS_PERIOD_MS = 2000L
    }

    private val main = Handler(Looper.getMainLooper())
    private var tun: ParcelFileDescriptor? = null
    private var proxy: LocalTlsProxy? = null
    private var dns: TunDnsForwarder? = null
    @Volatile private var state = "stopped"
    @Volatile private var detail = ""

    private var tick = 0
    private val ticker = object : Runnable {
        override fun run() {
            if (state == "running") detail = MeshSyncEngine.status()
            if (state == "running" && tick++ % 5 == 0) {        // every ~10 s
                Thread({
                    try { MeshSyncEngine.writeDirectory(this@PepeVpnService) }
                    catch (e: Throwable) { Log.w(TAG, "directory snapshot failed", e) }
                }, "pepenet-dir").start()
            }
            broadcast()
            updateNotification()
            main.postDelayed(this, STATUS_PERIOD_MS)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> shutdown()
            else -> connect()
        }
        return START_NOT_STICKY
    }

    private fun connect() {
        if (state == "running" || state == "starting") { goForeground(); broadcast(); return }
        state = "starting"
        detail = "Starting PepeNet node…"
        goForeground()
        main.removeCallbacks(ticker)
        main.post(ticker)

        Thread({
            try {
                if (!MeshSyncEngine.start(this)) {
                    fail("Native node failed to start (see log)")
                    return@Thread
                }
                val p = LocalTlsProxy().also { it.start() }
                proxy = p
                val builder = Builder()
                    .setSession("PepeNet")
                    .setMtu(1500)
                    .addAddress(TunDnsForwarder.TUN_ADDR, 32)
                    .addDnsServer(TunDnsForwarder.DNS_ADDR)
                    .addRoute(TunDnsForwarder.DNS_ADDR, 32)
                    .setBlocking(true)
                    .setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", LocalTlsProxy.PORT))
                    .setConfigureIntent(openAppIntent())
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
                // our own sockets (chain peers, origins, upstream DNS) bypass the VPN
                builder.addDisallowedApplication(packageName)
                val fd = builder.establish()
                if (fd == null) {
                    fail("VPN permission was revoked")
                    return@Thread
                }
                tun = fd
                dns = TunDnsForwarder(fd, { underlyingDnsServers() }) { protect(it) }.also { it.start() }
                state = "running"
                detail = MeshSyncEngine.status()
                Log.i(TAG, "connected")
            } catch (e: Exception) {
                Log.e(TAG, "connect failed", e)
                fail(e.message ?: e.javaClass.simpleName)
            }
        }, "pepenet-connect").start()
    }

    private fun fail(msg: String) {
        state = "error"
        detail = msg
        broadcast()
        teardownVpn()
    }

    private fun underlyingDnsServers(): List<InetAddress> {
        val found = mutableListOf<InetAddress>()
        try {
            val cm = getSystemService(ConnectivityManager::class.java)
            // the phone's real network (not our VPN), so DNS follows Wi-Fi <-> mobile switches
            for (net in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(net) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) continue
                cm.getLinkProperties(net)?.dnsServers?.let(found::addAll)
            }
        } catch (e: Exception) {
            Log.w(TAG, "could not read system DNS", e)
        }
        // the tunnel is IPv4-only; keep v4 servers first, then public fallbacks
        val ordered = found.filterIsInstance<Inet4Address>() + found.filterNot { it is Inet4Address }
        return (ordered + listOf(
            InetAddresses.parseNumericAddress("1.1.1.1"),
            InetAddresses.parseNumericAddress("8.8.8.8"),
        )).distinct()
    }

    private fun teardownVpn() {
        dns?.stop(); dns = null
        proxy?.stop(); proxy = null
        try { tun?.close() } catch (_: Exception) {}
        tun = null
    }

    private fun shutdown() {
        main.removeCallbacks(ticker)
        teardownVpn()
        MeshSyncEngine.stop()
        state = "stopped"
        detail = ""
        broadcast()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        // fresh process next time: the C engines hold process-wide state
        main.postDelayed({ Process.killProcess(Process.myPid()) }, 500)
    }

    override fun onRevoke() {
        // another VPN took over, or the user disconnected from system settings
        shutdown()
    }

    override fun onDestroy() {
        main.removeCallbacks(ticker)
        teardownVpn()
        super.onDestroy()
    }

    private fun broadcast() {
        val log = try { if (state != "stopped") MeshSyncEngine.recentLog() else "" } catch (_: Throwable) { "" }
        sendBroadcast(Intent(ACTION_STATUS).setPackage(packageName)
            .putExtra(EXTRA_STATE, state)
            .putExtra(EXTRA_DETAIL, detail)
            .putExtra(EXTRA_LOG, log))
    }

    // ── notification ────────────────────────────────────────────────────────
    private fun openAppIntent(): PendingIntent = PendingIntent.getActivity(
        this, 0, Intent(this, MainActivity::class.java),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    private fun buildNotification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "PepeNet connection", NotificationManager.IMPORTANCE_LOW)
            )
        }
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_pepenet)
            .setContentTitle(if (state == "running") "PepeNet connected" else "PepeNet")
            .setContentText(detail.ifEmpty { state })
            .setContentIntent(openAppIntent())
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }

    private fun goForeground() {
        val n = buildNotification()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
    }

    private fun updateNotification() {
        if (state == "stopped") return
        try {
            getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification())
        } catch (_: Exception) {}
    }
}

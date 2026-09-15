package com.example.pepenet.vpn

import android.util.Log
import com.example.pepenet.core.PepeCore
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.util.Locale
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * The HTTP proxy the VPN hands to Android (VpnService.Builder.setHttpProxy), so
 * browsers send every request here instead of resolving .pepe themselves:
 *
 *  - `CONNECT name.pepe:443`  → the native DANE proxy's CONNECT front door
 *    (127.0.0.1:8444). It verifies the real origin against the owner's on-chain
 *    TLSA pin and presents a leaf signed by the local ".pepe-only" root CA.
 *  - `GET http://name.pepe/…` → same front door (it answers 301 → https).
 *  - anything else            → passed straight through (plain forward proxy),
 *    so normal browsing is unaffected.
 *
 * Listens on loopback only.
 */
class LocalTlsProxy(private val port: Int = PORT) {

    companion object {
        const val PORT = 8480
        private const val TAG = "PepeNetProxy"
        private const val MAX_HEAD = 16 * 1024
        private const val PEPE_SUFFIX = ".pepe"
    }

    @Volatile private var server: ServerSocket? = null
    private var pool: ExecutorService? = null

    fun start() {
        if (server != null) return
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 128)
        server = ss
        val exec = Executors.newCachedThreadPool()
        pool = exec
        exec.execute {
            while (!ss.isClosed) {
                val client = try { ss.accept() } catch (e: SocketException) { break }
                exec.execute { handle(client) }
            }
        }
        Log.i(TAG, "system proxy on 127.0.0.1:$port")
    }

    fun stop() {
        try { server?.close() } catch (_: Exception) {}
        server = null
        pool?.shutdownNow()
        pool = null
    }

    private fun handle(client: Socket) {
        client.use { c ->
            try {
                c.soTimeout = 15_000
                val cin = c.getInputStream()
                val (head, extra) = readHead(cin) ?: return
                val headText = String(head, Charsets.ISO_8859_1)
                val requestLine = headText.substringBefore("\r\n")
                val parts = requestLine.split(" ")
                if (parts.size < 3) return
                val method = parts[0].uppercase(Locale.ROOT)
                val target = parts[1]

                if (method == "CONNECT") {
                    val host = target.substringBeforeLast(":").trim('[', ']')
                    val port = target.substringAfterLast(":", "443").toIntOrNull() ?: 443
                    if (isPepe(host)) {
                        // native front door speaks CONNECT itself: forward verbatim
                        val front = dial(c, "127.0.0.1", PepeCore.CONNECT_PORT) ?: return
                        tunnel(c, front, head + extra, null)
                    } else {
                        val upstream = dial(c, host, port) ?: return
                        tunnel(c, upstream, extra,
                            "HTTP/1.1 200 Connection established\r\n\r\n".toByteArray())
                    }
                    return
                }

                // absolute-form plain HTTP: http://host[:port]/path
                if (!target.startsWith("http://", ignoreCase = true)) {
                    reply(c.getOutputStream(), "400 Bad Request")
                    return
                }
                val afterScheme = target.substring(7)
                val authority = afterScheme.substringBefore("/")
                val path = "/" + afterScheme.substringAfter("/", "")
                val host = authority.substringBeforeLast(":")
                    .takeIf { authority.contains(":") } ?: authority
                val port = if (authority.contains(":"))
                    authority.substringAfterLast(":").toIntOrNull() ?: 80 else 80

                if (isPepe(host)) {
                    // .pepe is HTTPS-only: send the browser to the padlocked URL
                    val out = c.getOutputStream()
                    out.write(("HTTP/1.1 301 Moved Permanently\r\nLocation: https://$authority$path\r\n" +
                        "Content-Length: 0\r\nConnection: close\r\n\r\n").toByteArray())
                    out.flush()
                    return
                }

                val upstream = dial(c, host, port) ?: return
                val rewritten = StringBuilder()
                rewritten.append(method).append(' ').append(path).append(' ')
                    .append(parts.drop(2).joinToString(" ")).append("\r\n")
                headText.substringAfter("\r\n").split("\r\n").forEach { line ->
                    if (line.isEmpty()) return@forEach
                    val name = line.substringBefore(":").trim().lowercase(Locale.ROOT)
                    if (name == "proxy-connection" || name == "connection" ||
                        name == "keep-alive" || name == "proxy-authorization") return@forEach
                    rewritten.append(line).append("\r\n")
                }
                rewritten.append("Connection: close\r\n\r\n")
                tunnel(c, upstream, rewritten.toString().toByteArray(Charsets.ISO_8859_1) + extra, null)
            } catch (e: Exception) {
                Log.d(TAG, "proxy connection ended: ${e.message}")
            }
        }
    }

    /** Connects upstream, or answers 502 to the browser and returns null. */
    private fun dial(client: Socket, host: String, port: Int): Socket? {
        val s = Socket()
        return try {
            s.connect(InetSocketAddress(host, port), 15_000)
            s
        } catch (e: Exception) {
            try { s.close() } catch (_: Exception) {}
            try { reply(client.getOutputStream(), "502 Bad Gateway") } catch (_: Exception) {}
            null
        }
    }

    private fun isPepe(host: String): Boolean {
        val h = host.lowercase(Locale.ROOT).trimEnd('.')
        return h.endsWith(PEPE_SUFFIX) && h.length > PEPE_SUFFIX.length
    }

    /** Reads up to the end of the request head; returns (head, bytes already read past it). */
    private fun readHead(input: InputStream): Pair<ByteArray, ByteArray>? {
        val buf = ByteArrayOutputStream()
        val chunk = ByteArray(4096)
        while (buf.size() < MAX_HEAD) {
            val n = input.read(chunk)
            if (n <= 0) return null
            buf.write(chunk, 0, n)
            val all = buf.toByteArray()
            val end = indexOfHeadEnd(all)
            if (end >= 0) {
                return all.copyOfRange(0, end) to all.copyOfRange(end, all.size)
            }
        }
        return null
    }

    private fun indexOfHeadEnd(b: ByteArray): Int {
        for (i in 0..b.size - 4) {
            if (b[i] == '\r'.code.toByte() && b[i + 1] == '\n'.code.toByte() &&
                b[i + 2] == '\r'.code.toByte() && b[i + 3] == '\n'.code.toByte()) return i + 4
        }
        return -1
    }

    private fun reply(out: OutputStream, status: String) {
        out.write("HTTP/1.1 $status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray())
        out.flush()
    }

    /** Pipes client ⇄ upstream until either side closes. */
    private fun tunnel(client: Socket, upstream: Socket, toUpstream: ByteArray, toClient: ByteArray?) {
        upstream.use { up ->
            client.soTimeout = 0
            up.soTimeout = 0
            up.tcpNoDelay = true
            client.tcpNoDelay = true
            if (toClient != null) {
                client.getOutputStream().write(toClient)
                client.getOutputStream().flush()
            }
            if (toUpstream.isNotEmpty()) {
                up.getOutputStream().write(toUpstream)
                up.getOutputStream().flush()
            }
            val t = Thread {
                copy(up.getInputStream(), client.getOutputStream())
                try { client.shutdownOutput() } catch (_: Exception) {}
            }
            t.isDaemon = true
            t.start()
            copy(client.getInputStream(), up.getOutputStream())
            try { up.shutdownOutput() } catch (_: Exception) {}
            t.join(60_000)
        }
    }

    private fun copy(input: InputStream, output: OutputStream) {
        val buf = ByteArray(16 * 1024)
        try {
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                output.write(buf, 0, n)
                output.flush()
            }
        } catch (_: Exception) {
        }
    }
}

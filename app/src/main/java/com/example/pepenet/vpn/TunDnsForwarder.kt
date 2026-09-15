package com.example.pepenet.vpn

import android.os.ParcelFileDescriptor
import android.util.Log
import com.example.pepenet.core.PepeCore
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.Locale
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * The VPN only routes one address into the tunnel: the DNS server it advertises
 * ([DNS_ADDR]). Every UDP/53 query that arrives is answered here:
 *   - `*.pepe`   → the native chain-backed resolver on 127.0.0.1:15353
 *   - everything → the phone's normal DNS servers ([upstreams], re-read per query)
 * All other traffic never enters the tunnel, so the VPN adds no overhead.
 */
class TunDnsForwarder(
    private val tun: ParcelFileDescriptor,
    private val upstreams: () -> List<InetAddress>,
    private val protect: (DatagramSocket) -> Boolean,
) {
    companion object {
        const val TUN_ADDR = "10.111.0.1"
        const val DNS_ADDR = "10.111.0.53"
        private const val TAG = "PepeNetDns"
    }

    @Volatile private var running = false
    private var reader: Thread? = null
    private var pool: ExecutorService? = null
    private val out = FileOutputStream(tun.fileDescriptor)
    private val dnsAddrBytes = InetAddress.getByName(DNS_ADDR).address

    fun start() {
        running = true
        val exec = Executors.newFixedThreadPool(8)
        pool = exec
        reader = Thread({
            val input = FileInputStream(tun.fileDescriptor)
            val packet = ByteArray(32767)
            while (running) {
                val n = try { input.read(packet) } catch (e: Exception) { break }
                if (n <= 0) {
                    if (n < 0) break
                    continue
                }
                val copy = packet.copyOf(n)
                try { exec.execute { handlePacket(copy) } } catch (_: Exception) { break }
            }
        }, "pepenet-tun").also { it.isDaemon = true; it.start() }
    }

    fun stop() {
        running = false
        pool?.shutdownNow()
        reader?.interrupt()
    }

    private fun handlePacket(p: ByteArray) {
        if (p.size < 28) return
        val version = (p[0].toInt() ushr 4) and 0xF
        if (version != 4) return
        val ihl = (p[0].toInt() and 0xF) * 4
        if (p[9].toInt() != 17 || p.size < ihl + 8) return           // UDP only
        for (i in 0 until 4) if (p[16 + i] != dnsAddrBytes[i]) return // to our DNS addr
        val dstPort = u16(p, ihl + 2)
        if (dstPort != 53) return
        val srcPort = u16(p, ihl)
        val udpLen = u16(p, ihl + 4)
        val payloadEnd = minOf(p.size, ihl + udpLen)
        if (payloadEnd <= ihl + 8) return
        val query = p.copyOfRange(ihl + 8, payloadEnd)
        val srcIp = p.copyOfRange(12, 16)

        val answer = resolve(query) ?: return
        writeResponse(srcIp, srcPort, answer)
    }

    private fun resolve(query: ByteArray): ByteArray? {
        val name = qname(query)
        val targets: List<InetSocketAddress> =
            if (name != null && (name == "pepe" || name.endsWith(".pepe"))) {
                listOf(InetSocketAddress(InetAddress.getByName("127.0.0.1"), PepeCore.DNS_PORT))
            } else {
                upstreams().map { InetSocketAddress(it, 53) }
            }
        for (t in targets) {
            try {
                DatagramSocket().use { s ->
                    if (!t.address.isLoopbackAddress) protect(s)
                    s.soTimeout = if (t.address.isLoopbackAddress) 4000 else 1500
                    s.send(DatagramPacket(query, query.size, t))
                    val buf = ByteArray(4096)
                    val resp = DatagramPacket(buf, buf.size)
                    s.receive(resp)
                    return buf.copyOf(resp.length)
                }
            } catch (e: Exception) {
                Log.d(TAG, "dns via $t failed for $name: ${e.message}")
            }
        }
        return null
    }

    /** First question name of a DNS message, lowercase, no trailing dot. */
    private fun qname(msg: ByteArray): String? {
        if (msg.size < 13) return null
        var i = 12
        val sb = StringBuilder()
        while (i < msg.size) {
            val len = msg[i].toInt() and 0xFF
            if (len == 0) break
            if (len and 0xC0 != 0 || i + 1 + len > msg.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(msg, i + 1, len, Charsets.ISO_8859_1))
            i += 1 + len
        }
        return sb.toString().lowercase(Locale.ROOT)
    }

    private fun writeResponse(dstIp: ByteArray, dstPort: Int, payload: ByteArray) {
        val total = 20 + 8 + payload.size
        val pkt = ByteArray(total)
        pkt[0] = 0x45
        put16(pkt, 2, total)
        put16(pkt, 4, 0)
        put16(pkt, 6, 0x4000)          // don't fragment
        pkt[8] = 64                    // TTL
        pkt[9] = 17                    // UDP
        System.arraycopy(dnsAddrBytes, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
        put16(pkt, 10, ipChecksum(pkt, 20))
        put16(pkt, 20, 53)
        put16(pkt, 22, dstPort)
        put16(pkt, 24, 8 + payload.size)
        put16(pkt, 26, 0)              // UDP checksum optional over IPv4
        System.arraycopy(payload, 0, pkt, 28, payload.size)
        synchronized(out) {
            try { out.write(pkt) } catch (e: Exception) { Log.d(TAG, "tun write: ${e.message}") }
        }
    }

    private fun u16(b: ByteArray, off: Int) =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    private fun put16(b: ByteArray, off: Int, v: Int) {
        b[off] = (v ushr 8).toByte()
        b[off + 1] = v.toByte()
    }

    private fun ipChecksum(b: ByteArray, len: Int): Int {
        var sum = 0L
        var i = 0
        while (i < len) {
            sum += u16(b, i).toLong()
            i += 2
        }
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }
}

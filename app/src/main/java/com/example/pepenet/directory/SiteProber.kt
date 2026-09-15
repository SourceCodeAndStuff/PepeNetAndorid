package com.example.pepenet.directory

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Base64
import com.example.pepenet.core.PepeCore
import com.example.pepenet.vpn.CertificateManager
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory

enum class SiteStatus { CHECKING, ONLINE, OFFLINE, TLS_FAILED, NO_WEBSITE }

data class SiteProbe(val status: SiteStatus, val icon: Bitmap? = null, val detail: String = "")

/**
 * Checks a site the same way the browser reaches it: through the native DANE
 * proxy (CONNECT front door), trusting ONLY the local PepeNet root. So
 * "online" means the origin answered AND matched its on-chain TLSA pin, and the
 * favicon bytes come over that verified connection.
 */
object SiteProber {
    private const val MAX_HTML = 256 * 1024
    private const val MAX_ICON = 512 * 1024

    private val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", PepeCore.CONNECT_PORT))
    @Volatile private var cached: Pair<Long, SSLSocketFactory>? = null

    private fun sslFor(context: Context): SSLSocketFactory? {
        val f = CertificateManager.caFile(context)
        if (!f.isFile) return null
        cached?.let { if (it.first == f.lastModified()) return it.second }
        val ca = f.inputStream().use { CertificateFactory.getInstance("X.509").generateCertificate(it) }
        val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("pepenet-root", ca)
        }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
        val factory = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }.socketFactory
        cached = f.lastModified() to factory
        return factory
    }

    fun probe(context: Context, site: Site): SiteProbe {
        if (!site.hasWebsite) return SiteProbe(SiteStatus.NO_WEBSITE, detail = "No website record")
        val ssl = sslFor(context) ?: return SiteProbe(SiteStatus.CHECKING, detail = "Waiting for certificate")
        val base = URL("https://${site.host}/")
        val (code, html) = try {
            fetch(ssl, base, MAX_HTML)
        } catch (e: javax.net.ssl.SSLException) {
            return SiteProbe(SiteStatus.TLS_FAILED, detail = "TLS: ${e.message ?: "handshake failed"}")
        } catch (e: Exception) {
            return SiteProbe(SiteStatus.OFFLINE, detail = e.message ?: "unreachable")
        }
        if (code == 502) return SiteProbe(SiteStatus.TLS_FAILED, detail = "Origin failed DANE verification")
        if (code >= 500 || code <= 0) return SiteProbe(SiteStatus.OFFLINE, detail = "HTTP $code")

        val icon = try { favicon(ssl, base, html) } catch (e: Exception) { null }
        return SiteProbe(SiteStatus.ONLINE, icon, "HTTP $code")
    }

    private fun favicon(ssl: SSLSocketFactory, base: URL, html: ByteArray?): Bitmap? {
        val candidates = mutableListOf<String>()
        if (html != null) {
            val text = String(html, Charsets.ISO_8859_1)
            val linkRe = Regex("<link\\b[^>]*>", RegexOption.IGNORE_CASE)
            val relRe = Regex("rel\\s*=\\s*[\"']?([^\"'>]*)", RegexOption.IGNORE_CASE)
            val hrefRe = Regex("href\\s*=\\s*[\"']([^\"']+)[\"']|href\\s*=\\s*([^\\s>]+)", RegexOption.IGNORE_CASE)
            for (m in linkRe.findAll(text)) {
                val tag = m.value
                val rel = relRe.find(tag)?.groupValues?.get(1)?.lowercase() ?: continue
                if (!rel.contains("icon")) continue
                val h = hrefRe.find(tag) ?: continue
                val href = h.groupValues[1].ifEmpty { h.groupValues[2] }
                if (href.isNotBlank()) candidates += href.replace("&amp;", "&")
            }
        }
        candidates += listOf("/favicon.ico", "/favicon.png")

        for (href in candidates) {
            val bytes: ByteArray? = if (href.startsWith("data:", ignoreCase = true)) {
                val comma = href.indexOf(',')
                if (comma < 0 || !href.substring(0, comma).contains(";base64")) null
                else try { Base64.decode(href.substring(comma + 1), Base64.DEFAULT) } catch (_: Exception) { null }
            } else {
                val url = try { URL(base, href) } catch (_: Exception) { null } ?: continue
                // only fetch over the verified .pepe path, never the open internet
                if (url.protocol != "https" || !url.host.lowercase().endsWith(".pepe")) continue
                try {
                    val (code, body) = fetch(ssl, url, MAX_ICON)
                    if (code in 200..299) body else null
                } catch (_: Exception) { null }
            }
            val bmp = bytes?.let { decode(it) }
            if (bmp != null) return bmp
        }
        return null
    }

    private fun decode(bytes: ByteArray): Bitmap? {
        val bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.size) ?: return null   // PNG/JPEG/GIF/WebP/ICO
        val size = 96
        return if (bmp.width > size || bmp.height > size) Bitmap.createScaledBitmap(bmp, size, size, true) else bmp
    }

    private fun fetch(ssl: SSLSocketFactory, url: URL, limit: Int): Pair<Int, ByteArray?> {
        val conn = url.openConnection(proxy) as HttpsURLConnection
        conn.sslSocketFactory = ssl
        conn.connectTimeout = 15_000
        conn.readTimeout = 20_000
        conn.instanceFollowRedirects = true
        conn.setRequestProperty("User-Agent", "PepeNet-Android/0.2.3")
        try {
            val code = conn.responseCode
            val stream: InputStream? = if (code >= 400) conn.errorStream else conn.inputStream
            val body = stream?.use { readLimited(it, limit) }
            return code to body
        } finally {
            conn.disconnect()
        }
    }

    private fun readLimited(input: InputStream, limit: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (out.size() < limit) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, minOf(n, limit - out.size()))
        }
        return out.toByteArray()
    }
}

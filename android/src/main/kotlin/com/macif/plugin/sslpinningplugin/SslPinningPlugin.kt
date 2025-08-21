package com.macif.plugin.sslpinningplugin

import android.net.http.X509TrustManagerExtensions
import android.os.Build
import androidx.annotation.RequiresApi
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.net.URL
import java.security.KeyStore
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.cert.CertificateEncodingException
import java.security.cert.X509Certificate
import java.text.ParseException
import java.util.concurrent.CompletableFuture
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import javax.security.cert.CertificateException

class SslPinningPlugin : MethodCallHandler, FlutterPlugin {

    private lateinit var channel: MethodChannel

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "ssl_pinning_plugin")
        channel.setMethodCallHandler(this);
    }

    @RequiresApi(Build.VERSION_CODES.N)
    override fun onMethodCall(call: MethodCall, result: Result) {
        try {
            when (call.method) {
                "check" -> handleCheckEvent(call, result)
                else -> result.notImplemented()
            }
        } catch (e: Exception) {
            result.error(e.toString(), "", "")
        }
    }

    @RequiresApi(Build.VERSION_CODES.N)
    @Throws(ParseException::class)
    private fun handleCheckEvent(call: MethodCall, result: Result) {

        val arguments: Map<Any?, Any?> = HashMap(call.arguments as Map<*, *>)
        val serverURL: String = arguments["url"] as String
        val allowedFingerprints: List<String> =
            ArrayList(arguments["fingerprints"] as List<*>).map { it.toString() }
        val httpMethod: String = arguments["httpMethod"] as String
        val httpHeaderArgs: Map<String, String> =
            HashMap(arguments["headers"] as Map<*, *>).mapKeys { it.key.toString() }
                .mapValues { it.value.toString() }
        val type: String = arguments["type"] as String
        val isProd: Boolean = arguments["isProd"] as Boolean

        val get: Boolean = CompletableFuture.supplyAsync {
            this.checkConnexion(
                serverURL, allowedFingerprints, httpHeaderArgs, type, httpMethod, isProd
            )
        }.get()

        if (get) {
            result.success("CONNECTION_SECURE")
        } else {
            result.error(
                "CONNECTION_NOT_SECURE",
                "Connection is not secure",
                "Fingerprint doesn't match"
            )
        }

    }

    private fun checkConnexion(
        serverURL: String,
        allowedFingerprints: List<String>,
        httpHeaderArgs: Map<String, String>,
        algorithm: String,
        httpMethod: String,
        isProd: Boolean,
    ): Boolean {
        if (allowedFingerprints.isEmpty()) return false

        val sha = this.getFingerprints(
            serverURL, httpHeaderArgs, algorithm, httpMethod, isProd
        )
        val normalizedAllowedFingerprint = normalizeFingerprints(allowedFingerprints)
        return normalizedAllowedFingerprint.any { sha.contains(it) }
    }

    private fun getFingerprints(
        serverURL: String,
        httpHeaderArgs: Map<String, String>,
        algorithm: String,
        httpMethod: String,
        isProd: Boolean
    ): Set<String> {
        val url = URL(serverURL)
        val conn = (url.openConnection() as HttpsURLConnection).apply {
            if (!isProd) {
                sslSocketFactory = createSocketFactory(listOf("TLSv1.2"))
                hostnameVerifier = HostnameVerifier { _, _ -> true }
            } else {
                hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier()
            }
            if (httpMethod.equals("Head", ignoreCase = true)) {
                requestMethod = "HEAD"
            }
            httpHeaderArgs.forEach { (k, v) -> setRequestProperty(k, v) }
        }

        conn.connect()

        val peer = conn.serverCertificates.map { it as X509Certificate }
        val peerFingerprints = peer.map { fingerprintHex(it, algorithm) }
        val trustManagerFactory =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
                init(null as KeyStore?)
            }
        val trustManager = trustManagerFactory.trustManagers.first() as X509TrustManager
        val trustManagerExtensions = X509TrustManagerExtensions(trustManager)
        val authType = peer.firstOrNull()?.publicKey?.algorithm ?: "RSA"
        val cleaned =
            trustManagerExtensions.checkServerTrusted(peer.toTypedArray(), authType, url.host)
        val cleanedFingerprint = cleaned.map { fingerprintHex(it, algorithm) }
        val allFingerprints = (peerFingerprints + cleanedFingerprint).toSet()
        return allFingerprints
    }

    private fun normalizeFingerprints(fps: List<String>): Set<String> =
        fps.map { it.uppercase().replace(Regex("[^A-F0-9]"), "") }.toSet()

    @Throws(NoSuchAlgorithmException::class, CertificateEncodingException::class)
    private fun fingerprintHex(cert: X509Certificate, algo: String): String =
        MessageDigest.getInstance(algo)
            .digest(cert.encoded)
            .joinToString("") { "%02X".format(it) }

    @Throws(CertificateException::class, NoSuchAlgorithmException::class)
    private fun anyCertInChainMatches(
        url: URL,
        conn: HttpsURLConnection,
        algo: String,
        allowed: Set<String>
    ): Boolean {
        val peer = conn.serverCertificates.map { it as X509Certificate }
        val peerFps = peer.map { fingerprintHex(it, algo) }

        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(null as KeyStore?)
        }
        val tm = tmf.trustManagers.first { it is X509TrustManager } as X509TrustManager
        val ext = X509TrustManagerExtensions(tm)
        val authType = peer.firstOrNull()?.publicKey?.algorithm ?: "RSA"
        val cleaned = ext.checkServerTrusted(peer.toTypedArray(), authType, url.host)
        val cleanedFps = cleaned.map { fingerprintHex(it, algo) }

        val allFps = (peerFps + cleanedFps).toSet()
        return allFps.any { it in allowed }
    }

    private fun createSocketFactory(protocols: List<String>): SSLSocketFactory {
        val sslContext: SSLContext = SSLContext.getInstance(protocols.first())
        val trustManagerFactory: TrustManagerFactory =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(null as KeyStore?)
        sslContext.init(null, trustManagerFactory.trustManagers, SecureRandom())
        return sslContext.socketFactory
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }
}

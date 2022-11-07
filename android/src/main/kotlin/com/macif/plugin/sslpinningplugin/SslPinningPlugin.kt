package com.macif.plugin.sslpinningplugin

import android.os.Build
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry.Registrar

import javax.net.ssl.HttpsURLConnection
import javax.security.cert.CertificateException
import java.io.IOException
import java.text.ParseException

import java.net.URL
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.cert.Certificate
import java.security.cert.CertificateEncodingException

import android.os.StrictMode

import androidx.annotation.NonNull
import androidx.annotation.RequiresApi
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionStage
import java.util.concurrent.TimeUnit
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate
import java.security.SecureRandom

class SslPinningPlugin: MethodCallHandler, FlutterPlugin {

    /// The MethodChannel that will the communication between Flutter and native Android
    ///
    /// This local reference serves to register the plugin with the Flutter Engine and unregister it
    /// when the Flutter Engine is detached from the Activity
    private lateinit var channel : MethodChannel

    override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {

        channel = MethodChannel(flutterPluginBinding.getFlutterEngine().getDartExecutor(), "ssl_pinning_plugin")
        channel.setMethodCallHandler(this);
    }

    companion object {
        @JvmStatic
        fun registerWith(registrar: Registrar){

            val channel = MethodChannel(registrar.messenger(), "ssl_pinning_plugin")
            channel.setMethodCallHandler(SslPinningPlugin())
        }
    }

    @RequiresApi(Build.VERSION_CODES.N)
    override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
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

        val arguments: HashMap<String, Any> = call.arguments as HashMap<String, Any>
        val serverURL: String = arguments.get("url") as String
        val allowedFingerprints: List<String> = arguments.get("fingerprints") as List<String>
        val httpMethod: String = arguments.get("httpMethod") as String
        val httpHeaderArgs: Map<String, String> = arguments.get("headers") as Map<String, String>
        val timeout: Int = arguments.get("timeout") as Int
        val type: String = arguments.get("type") as String
        val isProd: Boolean = arguments.get("isProd") as Boolean

        val get: Boolean = CompletableFuture.supplyAsync { this.checkConnexion(serverURL, allowedFingerprints, httpHeaderArgs, timeout, type, httpMethod, isProd) }.get()

        if(get) {
            result.success("CONNECTION_SECURE")
        }else {
            result.error("CONNECTION_NOT_SECURE", "Connection is not secure", "Fingerprint doesn't match")
        }

    }

    @RequiresApi(Build.VERSION_CODES.N)
    fun checkConnexion(serverURL: String, allowedFingerprints: List<String>, httpHeaderArgs: Map<String, String>, timeout: Int, type: String, httpMethod: String, isProd: Boolean): Boolean {
        val sha: String = this.getFingerprint(serverURL, timeout, httpHeaderArgs, type, httpMethod, isProd)
        return allowedFingerprints.map { fp -> fp.toUpperCase().replace("\\s".toRegex(), "") }.contains(sha)
    }

    @RequiresApi(Build.VERSION_CODES.N)
    @Throws(IOException::class, NoSuchAlgorithmException::class, CertificateException::class, CertificateEncodingException::class)
    private fun getFingerprint(httpsURL: String, connectTimeout: Int, httpHeaderArgs: Map<String, String>, type: String, httpMethod: String, isProd: Boolean): String {

        val url = URL(httpsURL)
        val httpClient: HttpsURLConnection;
        if(isProd) {
            httpClient = (url.openConnection() as HttpsURLConnection)
        } else {
            httpClient = (url.openConnection() as HttpsURLConnection).apply {
                sslSocketFactory = createSocketFactory(listOf("TLSv1.2"))
                hostnameVerifier = HostnameVerifier { _, _ -> true }
                readTimeout = 5000
            }
        }

        if (httpMethod == "Head") httpClient.setRequestMethod("HEAD");

        httpHeaderArgs.forEach { key, value -> httpClient.setRequestProperty(key, value) }
        httpClient.connect()

        val cert: Certificate = httpClient.getServerCertificates()[0] as Certificate

        httpClient.disconnect()

        return this.hashString(type, cert.getEncoded())

    }

    private fun createSocketFactory(protocols: List<String>) =
        SSLContext.getInstance(protocols[0]).apply {
            val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                override fun checkClientTrusted(certs: Array<X509Certificate>, authType: String) = Unit
                override fun checkServerTrusted(certs: Array<X509Certificate>, authType: String) = Unit
            })
            init(null, trustAllCerts, SecureRandom())
        }.socketFactory

    private fun hashString(type: String, input: ByteArray) =
            MessageDigest
                    .getInstance(type)
                    .digest(input)
                    .map { String.format("%02X", it) }
                    .joinToString(separator = "")


    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }
}

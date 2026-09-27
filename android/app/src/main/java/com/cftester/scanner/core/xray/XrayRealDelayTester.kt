package com.cftester.scanner.core.xray

import com.cftester.scanner.core.model.ParsedConfig
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

data class RealDelayResult(
    val ip: String = "",
    val delayMs: Long = -1L,
    val httpCode: Int = 0,
    val status: String = "FAILED",        // "SUCCESS", "FAILED", "TIMEOUT", "ERROR"
    val realStatus: String = "FAIL",      // "204 RealDelay OK", "HTTP 200", etc.
    val error: String? = null
)

object PortManager {
    fun getFreePort(): Int {
        ServerSocket(0).use { socket ->
            socket.reuseAddress = true
            return socket.localPort
        }
    }

    fun getFreePorts(count: Int): List<Int> {
        require(count >= 0) { "Port count must be non-negative" }
        if (count == 0) return emptyList()
        val sockets = mutableListOf<ServerSocket>()
        try {
            for (i in 0 until count) {
                val s = ServerSocket(0)
                s.reuseAddress = true
                sockets.add(s)
            }
            return sockets.map { it.localPort }
        } finally {
            for (s in sockets) {
                try { s.close() } catch (_: Exception) {}
            }
        }
    }
}

object XrayRealDelayTester {

    fun isXrayAvailable(nativeLibDir: File): Boolean {
        val xrayBinary = File(nativeLibDir, "libxray.so")
        return xrayBinary.exists() && xrayBinary.isFile
    }

    suspend fun waitForPortReady(
        port: Int,
        timeoutMs: Long = 2000L,
        pollIntervalMs: Long = 25L
    ): Boolean = withContext(Dispatchers.IO) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress("127.0.0.1", port), 50)
                    return@withContext true
                }
            } catch (_: Exception) {
                delay(pollIntervalMs)
            }
        }
        false
    }

    suspend fun testRealDelay(
        nativeLibDir: File,
        cacheDir: File,
        parsed: ParsedConfig,
        cleanIp: String,
        timeoutMs: Long = 4000L,
        targetUrl: String = "http://connectivitycheck.gstatic.com/generate_204"
    ): Long = withContext(Dispatchers.IO) {
        val res = testSingleRealDelay(nativeLibDir, cacheDir, parsed, cleanIp, timeoutMs, targetUrl)
        if (res.status == "SUCCESS") res.delayMs else -1L
    }

    suspend fun testSingleRealDelay(
        nativeLibDir: File,
        cacheDir: File,
        parsed: ParsedConfig,
        cleanIp: String,
        timeoutMs: Long = 4000L,
        targetUrl: String = "http://connectivitycheck.gstatic.com/generate_204"
    ): RealDelayResult = withContext(Dispatchers.IO) {
        val xrayBinary = File(nativeLibDir, "libxray.so")
        if (!xrayBinary.exists() || !xrayBinary.isFile) {
            return@withContext RealDelayResult(
                ip = cleanIp,
                status = "ERROR",
                error = "Xray binary not found: ${xrayBinary.absolutePath}"
            )
        }

        val httpPort = PortManager.getFreePort()
        val socksPort = PortManager.getFreePort()
        val configContent = XrayConfigGenerator.generateConfig(parsed, cleanIp, httpPort, socksPort)
        val configFile = File(cacheDir, "xray_${httpPort}_${System.currentTimeMillis()}.json")
        var process: Process? = null

        try {
            configFile.writeText(configContent)
            configFile.deleteOnExit()

            val pb = ProcessBuilder(xrayBinary.absolutePath, "run", "-c", configFile.absolutePath)
            pb.directory(cacheDir)
            pb.environment()["TMPDIR"] = cacheDir.absolutePath
            val proc = pb.start()
            process = proc
            startStreamDrainers(proc)

            val isBound = waitForPortReady(httpPort, timeoutMs = 2000L)
            if (!isBound) {
                return@withContext RealDelayResult(
                    ip = cleanIp,
                    status = "FAILED",
                    error = "Xray inbound port failed to bind within timeout"
                )
            }

            probeSingleProxy(cleanIp, httpPort, timeoutMs, targetUrl)
        } catch (e: Exception) {
            RealDelayResult(
                ip = cleanIp,
                status = "FAILED",
                error = e.message ?: e.toString()
            )
        } finally {
            safeDestroyProcess(process)
            try { configFile.delete() } catch (_: Exception) {}
        }
    }

    suspend fun testBatchRealDelay(
        nativeLibDir: File,
        cacheDir: File,
        parsed: ParsedConfig,
        cleanIps: List<String>,
        timeoutMs: Long = 4000L,
        targetUrl: String = "http://connectivitycheck.gstatic.com/generate_204",
        onResult: ((String, RealDelayResult) -> Unit)? = null
    ): Map<String, RealDelayResult> = withContext(Dispatchers.IO) {
        if (cleanIps.isEmpty()) return@withContext emptyMap()

        val xrayBinary = File(nativeLibDir, "libxray.so")
        if (!xrayBinary.exists() || !xrayBinary.isFile) {
            val errRes = RealDelayResult(
                status = "ERROR",
                error = "Xray binary not found: ${xrayBinary.absolutePath}"
            )
            val map = cleanIps.associateWith { errRes.copy(ip = it) }
            map.forEach { (ip, res) -> onResult?.invoke(ip, res) }
            return@withContext map
        }

        val ports = PortManager.getFreePorts(cleanIps.size)
        val configContent = XrayConfigGenerator.generateBatchConfig(parsed, cleanIps, ports)
        val configFile = File(cacheDir, "xray_batch_${ports[0]}_${System.currentTimeMillis()}.json")
        var process: Process? = null
        val results = ConcurrentHashMap<String, RealDelayResult>()

        try {
            configFile.writeText(configContent)
            configFile.deleteOnExit()

            val pb = ProcessBuilder(xrayBinary.absolutePath, "run", "-c", configFile.absolutePath)
            pb.directory(cacheDir)
            pb.environment()["TMPDIR"] = cacheDir.absolutePath
            val proc = pb.start()
            process = proc
            startStreamDrainers(proc)

            val isBound = waitForPortReady(ports[0], timeoutMs = 2500L)
            if (!isBound) {
                val bindErr = RealDelayResult(
                    status = "FAILED",
                    error = "Batch inbounds failed to bind within timeout"
                )
                val map = cleanIps.associateWith { bindErr.copy(ip = it) }
                map.forEach { (ip, res) -> onResult?.invoke(ip, res) }
                return@withContext map
            }

            coroutineScope {
                cleanIps.zip(ports).map { (ip, port) ->
                    launch(Dispatchers.IO) {
                        val res = probeSingleProxy(ip, port, timeoutMs, targetUrl)
                        results[ip] = res
                        onResult?.invoke(ip, res)
                    }
                }.joinAll()
            }
        } catch (e: Exception) {
            cleanIps.forEach { ip ->
                if (!results.containsKey(ip)) {
                    val res = RealDelayResult(
                        ip = ip,
                        status = "FAILED",
                        error = e.message ?: e.toString()
                    )
                    results[ip] = res
                    onResult?.invoke(ip, res)
                }
            }
        } finally {
            safeDestroyProcess(process)
            try { configFile.delete() } catch (_: Exception) {}
        }

        results.toMap()
    }

    fun probeSingleProxy(
        cleanIp: String,
        httpPort: Int,
        timeoutMs: Long,
        targetUrl: String
    ): RealDelayResult {
        return try {
            val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", httpPort))
            val client = OkHttpClient.Builder()
                .proxy(proxy)
                .connectTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .readTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .callTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .build()

            val request = Request.Builder()
                .url(targetUrl)
                .header("User-Agent", "Mozilla/5.0 (Android; Mobile)")
                .build()

            val tStart = System.nanoTime()
            client.newCall(request).execute().use { resp ->
                val delay = (System.nanoTime() - tStart) / 1_000_000L
                val code = resp.code
                val isSuccess = code == 200 || code == 204
                RealDelayResult(
                    ip = cleanIp,
                    delayMs = if (isSuccess) delay else -1L,
                    httpCode = code,
                    status = if (isSuccess) "SUCCESS" else "FAILED",
                    realStatus = if (isSuccess) "$code RealDelay OK" else "HTTP $code"
                )
            }
        } catch (e: Exception) {
            RealDelayResult(
                ip = cleanIp,
                delayMs = -1L,
                status = "FAILED",
                realStatus = "FAIL",
                error = e.message ?: e.toString()
            )
        }
    }

    private fun startStreamDrainers(proc: Process) {
        val drainScope = CoroutineScope(Dispatchers.IO)
        drainScope.launch { drainStream(proc.inputStream) }
        drainScope.launch { drainStream(proc.errorStream) }
    }

    private fun drainStream(stream: InputStream) {
        try {
            stream.use { input ->
                val buf = ByteArray(1024)
                while (input.read(buf) != -1) { /* discard */ }
            }
        } catch (_: Exception) {}
    }

    private fun safeDestroyProcess(proc: Process?) {
        if (proc == null) return
        try {
            proc.destroy()
            if (!proc.waitFor(400, TimeUnit.MILLISECONDS)) {
                proc.destroyForcibly()
                proc.waitFor(300, TimeUnit.MILLISECONDS)
            }
        } catch (_: Exception) {
            try { proc.destroyForcibly() } catch (_: Exception) {}
        }
    }
}

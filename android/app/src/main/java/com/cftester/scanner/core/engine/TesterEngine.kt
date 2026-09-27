package com.cftester.scanner.core.engine

import com.cftester.scanner.core.model.ParsedConfig
import com.cftester.scanner.core.model.ScanCandidate
import com.cftester.scanner.core.model.ScanConfig
import com.cftester.scanner.core.model.ScanProgress
import com.cftester.scanner.core.model.ScanResult
import com.cftester.scanner.core.parser.ConfigParser
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket

class TesterEngine {

    private val _isRunning = MutableStateFlow(false)
    val isRunning = _isRunning.asStateFlow()

    private val _isPaused = MutableStateFlow(false)
    val isPaused = _isPaused.asStateFlow()

    val _cancelRequested = AtomicBoolean(false)

    private val _progressFlow = MutableSharedFlow<ScanProgress>(extraBufferCapacity = 64)
    val progressFlow = _progressFlow.asSharedFlow()

    private val _workingResultFlow = MutableSharedFlow<ScanResult>(extraBufferCapacity = 128)
    val workingResultFlow = _workingResultFlow.asSharedFlow()

    private val workingResults = mutableListOf<ScanResult>()
    private val workingLock = Any()

    fun pause() {
        _isPaused.value = true
    }

    fun resume() {
        _isPaused.value = false
    }

    fun stop() {
        _cancelRequested.set(true)
        _isRunning.value = false
        _isPaused.value = false
    }

    fun buildVlessPayload(
        userUuid: String,
        targetHost: String = "connectivitycheck.gstatic.com",
        targetPort: Int = 80,
        httpPath: String = "/generate_204"
    ): ByteArray {
        return VlessPacketBuilder.build(userUuid, targetHost, targetPort, httpPath)
    }

    fun buildWsFrame(payload: ByteArray): ByteArray {
        return WebSocketFrameBuilder.buildBinaryFrame(payload)
    }

    suspend fun runScan(
        candidates: List<ScanCandidate>,
        config: ParsedConfig,
        concurrency: Int = 50,
        timeoutSec: Float = 2.5f,
        targetUrl: String = "http://connectivitycheck.gstatic.com/generate_204"
    ): List<ScanResult> = withContext(Dispatchers.IO) {
        _isRunning.value = true
        _isPaused.value = false
        _cancelRequested.set(false)

        synchronized(workingLock) { workingResults.clear() }

        val testedCount = AtomicInteger(0)
        val totalCount = candidates.size
        val startTime = System.currentTimeMillis()
        val semaphore = Semaphore(concurrency.coerceIn(1, 300))

        coroutineScope {
            val jobs = candidates.map { candidate ->
                launch {
                    if (_cancelRequested.get()) return@launch

                    semaphore.withPermit {
                        while (_isPaused.value && !_cancelRequested.get()) {
                            delay(200)
                        }
                        if (_cancelRequested.get()) return@withPermit

                        val result = testSingleIp(
                            ip = candidate.ip,
                            prefix = candidate.prefix,
                            config = config,
                            timeoutSec = timeoutSec,
                            targetUrl = targetUrl
                        )

                        val currentTested = testedCount.incrementAndGet()
                        if (result.status == "SUCCESS") {
                            synchronized(workingLock) {
                                workingResults.add(result)
                                workingResults.sortBy { if (it.googleLatencyMs > 0) it.googleLatencyMs else 99999f }
                            }
                            _workingResultFlow.emit(result)
                        }

                        val elapsed = (System.currentTimeMillis() - startTime).coerceAtLeast(100) / 1000f
                        val speed = (currentTested / elapsed * 10).toInt() / 10f

                        val latestLatency = if (result.googleLatencyMs > 0) result.googleLatencyMs else result.totalLatencyMs
                        _progressFlow.emit(
                            ScanProgress(
                                tested = currentTested,
                                total = totalCount,
                                working = synchronized(workingLock) { workingResults.size },
                                speed = speed,
                                latestIp = candidate.ip,
                                latestStatus = result.status,
                                latestLatency = latestLatency
                            )
                        )
                    }
                }
            }
            jobs.joinAll()
        }

        _isRunning.value = false
        synchronized(workingLock) {
            workingResults.sortBy { if (it.googleLatencyMs > 0) it.googleLatencyMs else 99999f }
            workingResults.toList()
        }
    }

    suspend fun runScan(
        candidates: List<ScanCandidate>,
        config: ScanConfig,
        onProgress: (ScanProgress) -> Unit = {},
        onResult: (ScanResult) -> Unit = {}
    ): List<ScanResult> = withContext(Dispatchers.IO) {
        val parsed = ParsedConfig(
            protocol = "vless",
            port = config.candidatePort,
            sni = config.candidateSni,
            host = config.candidateHost,
            path = config.candidatePath,
            transport = config.candidateTransport,
            security = config.candidateTls
        )

        val progressJob = launch {
            progressFlow.collect { progress ->
                onProgress(progress)
            }
        }
        val resultJob = launch {
            workingResultFlow.collect { res ->
                onResult(res)
            }
        }

        val results = runScan(
            candidates = candidates,
            config = parsed,
            concurrency = config.concurrency,
            timeoutSec = config.timeoutSec,
            targetUrl = config.targetUrl
        )

        progressJob.cancel()
        resultJob.cancel()
        results
    }

    suspend fun testSingleIp(
        ip: String,
        prefix: String = "",
        config: ParsedConfig,
        timeoutSec: Float = 2.5f,
        targetUrl: String = "http://connectivitycheck.gstatic.com/generate_204"
    ): ScanResult = withContext(Dispatchers.IO) {
        val cleanIp = ip.trim().removeSurrounding("[", "]")
        val port = config.port
        val sni = config.getSniOrHost()
        val hostHeader = if (config.getHostHeader().contains(":") && !config.getHostHeader().startsWith("[")) {
            "[${config.getHostHeader()}]"
        } else {
            config.getHostHeader()
        }
        val targetUri = try { java.net.URI(targetUrl) } catch (_: Exception) { null }
        val targetHost = targetUri?.host ?: "connectivitycheck.gstatic.com"
        val targetPath = targetUri?.rawPath?.ifEmpty { "/generate_204" } ?: "/generate_204"
        val timeoutMs = (timeoutSec * 1000).toInt().coerceAtLeast(1)

        var tcpMs = 0f
        var tlsMs = 0f
        var wsMs = 0f
        var vlessMs = 0f
        var googleMs = 0f
        var httpCode = 0
        var status = "FAILED"
        var googleStatus = "FAIL"
        var errorMsg = ""

        val tStart = System.nanoTime()
        var rawSocket: Socket? = null

        try {
            // Stage 1: TCP Handshake Connect
            val t0 = System.nanoTime()
            val socket = Socket()
            rawSocket = socket
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(cleanIp, port), timeoutMs)
            tcpMs = (System.nanoTime() - t0) / 1_000_000f

            // Stage 2: TLS SNI Handshake via SSLSocket
            val finalSocket: Socket = if (config.security in listOf("tls", "reality")) {
                val t1 = System.nanoTime()
                val sslContext = SslHelper.createTrustAllSslContext()
                val sslSocket = sslContext.socketFactory.createSocket(
                    socket,
                    cleanIp,
                    port,
                    true
                ) as SSLSocket

                val params = sslSocket.sslParameters
                if (!ConfigParser.isIp(sni)) {
                    params.serverNames = listOf(SNIHostName(sni))
                }
                sslSocket.sslParameters = params
                sslSocket.soTimeout = timeoutMs
                sslSocket.startHandshake()
                tlsMs = (System.nanoTime() - t1) / 1_000_000f
                sslSocket
            } else {
                socket.soTimeout = timeoutMs
                socket
            }

            // Stage 3: HTTP/1.1 WebSocket Upgrade Check or XHTTP Probe
            val t2 = System.nanoTime()
            val out = finalSocket.getOutputStream()
            val input = finalSocket.getInputStream()

            val reqPath = if (config.path.startsWith("/")) config.path else "/${config.path}"
            val wsKey = SslHelper.generateWebSocketKey()

            val httpReq = when {
                config.transport in listOf("xhttp", "splithttp") -> {
                    "POST $reqPath HTTP/1.1\r\n" +
                    "Host: $hostHeader\r\n" +
                    "User-Agent: Mozilla/5.0 (Android; Mobile)\r\n" +
                    "Accept-Encoding: gzip, deflate, br, zstd\r\n" +
                    "Content-Type: application/octet-stream\r\n" +
                    "Content-Length: 0\r\n" +
                    "Connection: close\r\n\r\n"
                }
                config.protocol == "direct" && ("cp.cloudflare.com" in sni || "generate_204" in reqPath) -> {
                    "GET /generate_204 HTTP/1.1\r\n" +
                    "Host: cp.cloudflare.com\r\n" +
                    "User-Agent: Mozilla/5.0 (Android; Mobile)\r\n" +
                    "Connection: close\r\n\r\n"
                }
                else -> {
                    "GET $reqPath HTTP/1.1\r\n" +
                    "Host: $hostHeader\r\n" +
                    "User-Agent: Mozilla/5.0 (Android; Mobile)\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Sec-WebSocket-Key: $wsKey\r\n" +
                    "Sec-WebSocket-Version: 13\r\n\r\n"
                }
            }

            out.write(httpReq.toByteArray(Charsets.US_ASCII))
            out.flush()

            val buffer = ByteArray(2048)
            val bytesRead = input.read(buffer)
            val respText = if (bytesRead > 0) String(buffer, 0, bytesRead, Charsets.ISO_8859_1) else ""
            val firstLine = respText.lineSequence().firstOrNull() ?: ""

            val parts = firstLine.split(" ")
            if (parts.size >= 2 && parts[1].all { it.isDigit() }) {
                httpCode = parts[1].toInt()
            }
            wsMs = (System.nanoTime() - t2) / 1_000_000f

            // Stage 4: Binary VLESS WS Google Tunnel Probe
            if (httpCode == 101) {
                val t3 = System.nanoTime()
                val vlessPayload = buildVlessPayload(
                    userUuid = config.uuid,
                    targetHost = targetHost,
                    targetPort = 80,
                    httpPath = targetPath
                )
                val wsFrame = buildWsFrame(vlessPayload)
                out.write(wsFrame)
                out.flush()

                val tunnelBuffer = ByteArray(2048)
                val tunnelBytes = try { input.read(tunnelBuffer) } catch (_: Exception) { 0 }
                val tunnelText = if (tunnelBytes > 0) String(tunnelBuffer, 0, tunnelBytes, Charsets.ISO_8859_1) else ""
                vlessMs = (System.nanoTime() - t3) / 1_000_000f

                if ("204" in tunnelText) {
                    googleStatus = "204 Google OK"
                    status = "SUCCESS"
                } else if ("200" in tunnelText) {
                    googleStatus = "200 Google OK"
                    status = "SUCCESS"
                } else {
                    googleStatus = "101 WS OK"
                    status = "SUCCESS"
                }
                googleMs = (System.nanoTime() - t2) / 1_000_000f
            } else if (httpCode in listOf(204, 200, 301, 302, 307, 308, 400, 403, 404, 405, 426)) {
                status = "SUCCESS"
                googleMs = wsMs
                googleStatus = when (httpCode) {
                    204 -> "204 No Content"
                    200 -> "200 OK"
                    403 -> "403 Origin OK"
                    404 -> "404 Origin OK"
                    in 300..399 -> "$httpCode CF Redirect"
                    else -> "$httpCode CF Edge"
                }
            } else {
                status = "FAILED"
                googleStatus = if (httpCode > 0) "HTTP $httpCode" else "NO_RESPONSE"
            }

        } catch (e: Exception) {
            status = when {
                e is java.net.SocketTimeoutException -> "TIMEOUT"
                e is java.net.ConnectException -> "REFUSED"
                else -> "FAILED"
            }
            googleStatus = when (status) {
                "TIMEOUT" -> "TIMEOUT"
                "REFUSED" -> "REFUSED"
                else -> "ERROR"
            }
            errorMsg = e.message ?: e.toString()
        } finally {
            try { rawSocket?.close() } catch (_: Exception) {}
        }

        val totalMs = (System.nanoTime() - tStart) / 1_000_000f
        val modLink = if (status == "SUCCESS") {
            val effLatency = if (googleMs > 0) googleMs else totalMs
            ConfigParser.generateModifiedLink(config, cleanIp, "${effLatency.toInt()}ms")
        } else ""

        ScanResult(
            ip = cleanIp,
            prefix = prefix,
            port = port,
            protocol = config.protocol.uppercase(),
            status = status,
            googleStatus = googleStatus,
            googleLatencyMs = if (status == "SUCCESS") googleMs else 0f,
            tcpLatencyMs = tcpMs,
            tlsLatencyMs = tlsMs,
            wsLatencyMs = wsMs,
            vlessLatencyMs = vlessMs,
            totalLatencyMs = totalMs,
            httpCode = httpCode,
            modifiedLink = modLink,
            errorMsg = errorMsg
        )
    }
}

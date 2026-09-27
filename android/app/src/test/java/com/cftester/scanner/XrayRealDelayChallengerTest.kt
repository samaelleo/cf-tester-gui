package com.cftester.scanner

import com.cftester.scanner.core.model.ParsedConfig
import com.cftester.scanner.core.xray.PortManager
import com.cftester.scanner.core.xray.XrayConfigGenerator
import com.cftester.scanner.core.xray.XrayRealDelayTester
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Empirical Challenger Stress & Verification Test Suite for Milestone 3 (F10).
 * Adversarially tests:
 * 1. Port allocation concurrency, zero/negative bounds, and re-binding reliability.
 * 2. Consecutive port allocation collision analysis.
 * 3. SIP002 Base64 encoding permutations, unpadded strings, URL encoding, legacy creds.
 * 4. Special character escaping in Trojan, VMess, and VLESS configurations.
 * 5. IPv6 bracket stripping with whitespace, dual brackets, and extreme subnets.
 * 6. Xray batch config generation bounds, size mismatches, and routing rule isolation.
 * 7. Active port readiness polling under delayed socket opening and timeout bounds.
 * 8. Missing binary and invalid directory handling in single and batch modes.
 * 9. Mock HTTP 200 vs 204 vs 500 error code discrimination in proxy probing.
 */
class XrayRealDelayChallengerTest {

    // =========================================================================
    // 1. PortManager Boundary, Concurrency & Rebind Stress
    // =========================================================================

    @Test
    fun testPortManagerZeroPorts() {
        val ports = PortManager.getFreePorts(0)
        assertTrue("PortManager.getFreePorts(0) must return empty list", ports.isEmpty())
    }

    @Test(expected = IllegalArgumentException::class)
    fun testPortManagerNegativePortsThrows() {
        PortManager.getFreePorts(-1)
    }

    @Test
    fun testPortManagerHighCountAllocation() {
        // Request 100 ports simultaneously
        val count = 100
        val ports = PortManager.getFreePorts(count)
        assertEquals(count, ports.size)
        assertEquals("All 100 batch ports must be distinct", count, ports.toSet().size)
        assertTrue("All ports must be in unprivileged dynamic range (1024..65535)", ports.all { it in 1024..65535 })
    }

    @Test
    fun testPortManagerImmediateRebindReliability() {
        // Verify that ports released by PortManager can immediately be bound by another ServerSocket
        val count = 15
        val ports = PortManager.getFreePorts(count)
        val boundSockets = mutableListOf<ServerSocket>()
        try {
            for (p in ports) {
                val s = ServerSocket(p)
                s.reuseAddress = true
                boundSockets.add(s)
            }
            assertEquals("All released ports must be immediately re-bindable", count, boundSockets.size)
        } finally {
            for (s in boundSockets) {
                try { s.close() } catch (_: Exception) {}
            }
        }
    }

    @Test
    fun testPortManagerHighConcurrencyStress() = runBlocking {
        // 20 concurrent coroutines each requesting 15 ports
        val concurrency = 20
        val portsPerJob = 15
        val jobs = (1..concurrency).map {
            async(Dispatchers.IO) {
                PortManager.getFreePorts(portsPerJob)
            }
        }
        val allResults = jobs.awaitAll()
        assertEquals(concurrency, allResults.size)
        for (portList in allResults) {
            assertEquals(portsPerJob, portList.size)
            assertEquals("Ports within each job must be unique", portsPerJob, portList.toSet().size)
            assertTrue("Ports must be in unprivileged range", portList.all { it in 1024..65535 })
        }
    }

    @Test
    fun testPortManagerConsecutiveGetFreePortDistinctness() {
        // Verify that calling getFreePort() in quick succession does not produce identical ports within the same call pair
        var collisionCount = 0
        val iterations = 50
        for (i in 1..iterations) {
            val p1 = PortManager.getFreePort()
            val p2 = PortManager.getFreePort()
            if (p1 == p2) {
                collisionCount++
            }
        }
        // Even if OS recycling could theoretically reuse, in practice ephemeral port allocator increments
        assertTrue("Port collision rate should be extremely low (got $collisionCount collisions out of $iterations)", collisionCount < 5)
    }

    // =========================================================================
    // 2. SIP002 & Shadowsocks Credential Parsing Permutations
    // =========================================================================

    @Test
    fun testSsCredsUnpaddedBase64() {
        // "chacha20-ietf-poly1305:mypass123" -> Base64 is Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpteXBhc3MxMjM=
        // Stripped padding '=':
        val unpadded = "Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpteXBhc3MxMjM"
        val (method, pass) = XrayConfigGenerator.extractSsCreds(unpadded)
        assertEquals("chacha20-ietf-poly1305", method)
        assertEquals("mypass123", pass)
    }

    @Test
    fun testSsCredsBase64WithLegacyHostPort() {
        // Base64 encoding of "aes-256-gcm:secretP@ss@1.2.3.4:8388"
        val full = "aes-256-gcm:secretP@ss@1.2.3.4:8388"
        val b64 = Base64.getEncoder().encodeToString(full.toByteArray())
        val (method, pass) = XrayConfigGenerator.extractSsCreds(b64)
        assertEquals("aes-256-gcm", method)
        assertEquals("secretP@ss", pass)
    }

    @Test
    fun testSsCredsPlainLegacyWithHostPort() {
        val plain = "2022-blake3-aes-128-gcm:ComplexPassword@104.16.24.1:8443"
        val (method, pass) = XrayConfigGenerator.extractSsCreds(plain)
        assertEquals("2022-blake3-aes-128-gcm", method)
        assertEquals("ComplexPassword", pass)
    }

    @Test
    fun testSsCredsSpecialCharactersInPassword() {
        // Password with colon is not supported by naive split, but with Base64 SIP002:
        val creds = "aes-128-gcm:pass:with:colons!@#"
        val b64 = Base64.getEncoder().encodeToString(creds.toByteArray())
        val (method, pass) = XrayConfigGenerator.extractSsCreds(b64)
        assertEquals("aes-128-gcm", method)
        assertEquals("pass:with:colons!@#", pass)
    }

    @Test
    fun testSsCredsPlainPasswordOnlyFallback() {
        val plainPass = "justAPasswordWithoutMethod"
        val (method, pass) = XrayConfigGenerator.extractSsCreds(plainPass)
        assertEquals("aes-256-gcm", method)
        assertEquals("justAPasswordWithoutMethod", pass)
    }

    @Test
    fun testSsCredsEmptyInputFallback() {
        val (method, pass) = XrayConfigGenerator.extractSsCreds("")
        assertEquals("aes-256-gcm", method)
        assertEquals("", pass)
    }

    // =========================================================================
    // 3. XrayConfigGenerator Outbound & JSON Structure Adversarial Tests
    // =========================================================================

    @Test
    fun testOutboundTrojanSpecialCharactersInPassword() {
        val complexPassword = "p@ss\"word'with\\slashes,quotes&persianرمز"
        val parsed = ParsedConfig(
            protocol = "trojan",
            uuid = complexPassword,
            host = "trojan.cf.com",
            port = 443,
            sni = "trojan.cf.com",
            security = "tls"
        )
        val configStr = XrayConfigGenerator.generateConfig(parsed, "1.1.1.1", 10808, 10809)
        val root = JSONObject(configStr)
        val outbound = root.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("trojan", outbound.getString("protocol"))
        val server = outbound.getJSONObject("settings").getJSONArray("servers").getJSONObject(0)
        assertEquals("1.1.1.1", server.getString("address"))
        assertEquals(443, server.getInt("port"))
        assertEquals(complexPassword, server.getString("password"))
    }

    @Test
    fun testOutboundVlessPostQuantumMlkemEncryption() {
        val parsed = ParsedConfig(
            protocol = "vless",
            uuid = "11111111-2222-3333-4444-555555555555",
            host = "pq.cf.com",
            port = 443,
            encryption = "mlkem768x25519",
            flow = "xtls-rprx-vision",
            security = "reality",
            pbk = "FakePbkKey123",
            sid = "abcd1234"
        )
        val configStr = XrayConfigGenerator.generateConfig(parsed, "104.16.24.1", 10808, 10809)
        val root = JSONObject(configStr)
        val outbound = root.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("vless", outbound.getString("protocol"))

        val user = outbound.getJSONObject("settings")
            .getJSONArray("vnext").getJSONObject(0)
            .getJSONArray("users").getJSONObject(0)
        assertEquals("mlkem768x25519", user.getString("encryption"))
        assertEquals("xtls-rprx-vision", user.getString("flow"))

        val streamSettings = outbound.getJSONObject("streamSettings")
        assertEquals("reality", streamSettings.getString("security"))
        val realitySettings = streamSettings.getJSONObject("realitySettings")
        assertEquals("FakePbkKey123", realitySettings.getString("publicKey"))
        assertEquals("abcd1234", realitySettings.getString("shortId"))
    }

    @Test
    fun testOutboundXhttpWithExtraMapAndMode() {
        val extraMap = mapOf("downloadSettings" to "{\"parallel\": 4}", "customHeader" to "customVal")
        val parsed = ParsedConfig(
            protocol = "vless",
            uuid = "11111111-2222-3333-4444-555555555555",
            host = "xhttp.example.com",
            port = 443,
            transport = "xhttp",
            path = "/xhttp-path",
            mode = "stream-up",
            extra = extraMap,
            security = "tls"
        )
        val configStr = XrayConfigGenerator.generateConfig(parsed, "104.16.24.1", 10808, 10809)
        val root = JSONObject(configStr)
        val outbound = root.getJSONArray("outbounds").getJSONObject(0)
        val streamSettings = outbound.getJSONObject("streamSettings")
        assertEquals("xhttp", streamSettings.getString("network"))

        val xhttpSettings = streamSettings.getJSONObject("xhttpSettings")
        assertEquals("/xhttp-path", xhttpSettings.getString("path"))
        assertEquals("xhttp.example.com", xhttpSettings.getString("host"))
        assertEquals("stream-up", xhttpSettings.getString("mode"))

        val extraJson = xhttpSettings.getJSONObject("extra")
        assertEquals("{\"parallel\": 4}", extraJson.getString("downloadSettings"))
        assertEquals("customVal", extraJson.getString("customHeader"))
    }

    @Test
    fun testOutboundGrpcTrimsLeadingSlash() {
        val parsed = ParsedConfig(
            protocol = "vless",
            uuid = "11111111-2222-3333-4444-555555555555",
            host = "grpc.cf.com",
            port = 443,
            transport = "grpc",
            path = "/my-custom-grpc-service",
            security = "tls"
        )
        val configStr = XrayConfigGenerator.generateConfig(parsed, "104.16.24.1", 10808, 10809)
        val root = JSONObject(configStr)
        val streamSettings = root.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
        assertEquals("grpc", streamSettings.getString("network"))
        val grpcSettings = streamSettings.getJSONObject("grpcSettings")
        assertEquals("my-custom-grpc-service", grpcSettings.getString("serviceName"))
        assertTrue(grpcSettings.getBoolean("multiMode"))
    }

    @Test
    fun testOutboundIpv6BracketStrippingVariations() {
        val parsed = ParsedConfig(protocol = "vless", uuid = "u1", port = 443)

        // 1. Standard bracketed
        val out1 = XrayConfigGenerator.buildOutbound(parsed, "[2606:4700::1]", "proxy")
        val addr1 = out1.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address")
        assertEquals("2606:4700::1", addr1)

        // 2. Unbracketed IPv6
        val out2 = XrayConfigGenerator.buildOutbound(parsed, "2606:4700::1", "proxy")
        val addr2 = out2.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address")
        assertEquals("2606:4700::1", addr2)

        // 3. Whitespace around bracketed IPv6
        val out3 = XrayConfigGenerator.buildOutbound(parsed, "  [2606:4700::1]  ", "proxy")
        val addr3 = out3.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address")
        assertEquals("2606:4700::1", addr3)

        // 4. IPv4 with whitespace
        val out4 = XrayConfigGenerator.buildOutbound(parsed, " 104.16.24.1 ", "proxy")
        val addr4 = out4.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address")
        assertEquals("104.16.24.1", addr4)
    }

    @Test
    fun testOutboundUnknownProtocolFallback() {
        val parsed = ParsedConfig(protocol = "unknown_proto", port = 443)
        val out = XrayConfigGenerator.buildOutbound(parsed, "104.16.24.1", "proxy")
        assertEquals("freedom", out.getString("protocol"))
    }

    // =========================================================================
    // 4. Batch Configuration Stress & Invariants
    // =========================================================================

    @Test(expected = IllegalArgumentException::class)
    fun testGenerateBatchConfigPortMismatchThrows() {
        val parsed = ParsedConfig(protocol = "vless", port = 443)
        val cleanIps = listOf("1.1.1.1", "2.2.2.2")
        val ports = listOf(10808) // Only 1 port for 2 IPs
        XrayConfigGenerator.generateBatchConfig(parsed, cleanIps, ports)
    }

    @Test
    fun testGenerateBatchConfigZeroCleanIps() {
        val parsed = ParsedConfig(protocol = "vless", port = 443)
        val configStr = XrayConfigGenerator.generateBatchConfig(parsed, emptyList(), emptyList())
        val root = JSONObject(configStr)
        assertEquals(0, root.getJSONArray("inbounds").length())
        assertEquals(1, root.getJSONArray("outbounds").length()) // direct outbound only
        assertEquals("direct", root.getJSONArray("outbounds").getJSONObject(0).getString("tag"))
        assertEquals(0, root.getJSONObject("routing").getJSONArray("rules").length())
    }

    @Test
    fun testGenerateBatchConfigLargeCount50Ips() {
        val parsed = ParsedConfig(
            protocol = "vless",
            uuid = "11111111-2222-3333-4444-555555555555",
            host = "worker.dev",
            port = 443,
            transport = "ws",
            security = "tls"
        )
        val count = 50
        val cleanIps = (1..count).map { "104.16.0.$it" }
        val ports = (20000 until 20000 + count).toList()

        val configStr = XrayConfigGenerator.generateBatchConfig(parsed, cleanIps, ports)
        val root = JSONObject(configStr)

        val inbounds = root.getJSONArray("inbounds")
        val outbounds = root.getJSONArray("outbounds")
        val rules = root.getJSONObject("routing").getJSONArray("rules")

        assertEquals(count, inbounds.length())
        assertEquals(count + 1, outbounds.length()) // count proxies + 1 direct
        assertEquals(count, rules.length())

        // Validate 1:1 mapping isolation
        for (i in 0 until count) {
            val inTag = "http-in-$i"
            val outTag = "proxy-$i"

            val inbound = inbounds.getJSONObject(i)
            assertEquals(inTag, inbound.getString("tag"))
            assertEquals(ports[i], inbound.getInt("port"))

            val outbound = outbounds.getJSONObject(i)
            assertEquals(outTag, outbound.getString("tag"))
            val targetAddr = outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address")
            assertEquals("104.16.0.${i + 1}", targetAddr)

            val rule = rules.getJSONObject(i)
            assertEquals(inTag, rule.getJSONArray("inboundTag").getString(0))
            assertEquals(outTag, rule.getString("outboundTag"))
        }

        // Direct outbound tag at the end
        assertEquals("direct", outbounds.getJSONObject(count).getString("tag"))
    }

    // =========================================================================
    // 5. Active Port Readiness Polling Stress
    // =========================================================================

    @Test
    fun testWaitForPortReadyDelayedSocketOpening() = runBlocking {
        val server = ServerSocket(0)
        val targetPort = server.localPort
        server.close() // Release to make it free

        // Launch delayed binder in coroutine
        val job = launch(Dispatchers.IO) {
            delay(100L)
            val lateServer = ServerSocket(targetPort)
            lateServer.reuseAddress = true
            delay(300L)
            lateServer.close()
        }

        val ready = XrayRealDelayTester.waitForPortReady(targetPort, timeoutMs = 800L, pollIntervalMs = 20L)
        assertTrue("Port must be detected as ready once bound after delay", ready)
        job.join()
    }

    @Test
    fun testWaitForPortReadyTightTimeoutBounds() = runBlocking {
        val unusedPort = PortManager.getFreePort()
        val timeoutMs = 150L
        val t0 = System.currentTimeMillis()
        val ready = XrayRealDelayTester.waitForPortReady(unusedPort, timeoutMs = timeoutMs, pollIntervalMs = 25L)
        val elapsed = System.currentTimeMillis() - t0

        assertFalse("Unbound port must return false", ready)
        assertTrue("Elapsed time ($elapsed ms) must respect timeout ($timeoutMs ms)", elapsed in 140..450)
    }

    // =========================================================================
    // 6. RealDelay Proxy Probing Error Code Discrimination
    // =========================================================================

    @Test
    fun testProbeSingleProxyHttp200Success() {
        val server = ServerSocket(0)
        val serverPort = server.localPort
        val serverThread = Thread {
            try {
                val socket = server.accept()
                val reader = socket.getInputStream().bufferedReader()
                while (true) {
                    val line = reader.readLine() ?: break
                    if (line.isEmpty()) break
                }
                val writer = socket.getOutputStream().bufferedWriter()
                writer.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                writer.flush()
                socket.close()
            } catch (_: Exception) {}
        }
        serverThread.start()

        try {
            val targetUrl = "http://127.0.0.1:$serverPort/test_200"
            val res = XrayRealDelayTester.probeSingleProxy(
                cleanIp = "127.0.0.1",
                httpPort = serverPort,
                timeoutMs = 1500L,
                targetUrl = targetUrl
            )
            assertEquals("SUCCESS", res.status)
            assertEquals(200, res.httpCode)
            assertEquals("200 RealDelay OK", res.realStatus)
            assertTrue(res.delayMs >= 0)
        } finally {
            server.close()
            serverThread.join(500)
        }
    }

    @Test
    fun testProbeSingleProxyHttp502Failure() {
        val server = ServerSocket(0)
        val serverPort = server.localPort
        val serverThread = Thread {
            try {
                val socket = server.accept()
                val reader = socket.getInputStream().bufferedReader()
                while (true) {
                    val line = reader.readLine() ?: break
                    if (line.isEmpty()) break
                }
                val writer = socket.getOutputStream().bufferedWriter()
                writer.write("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                writer.flush()
                socket.close()
            } catch (_: Exception) {}
        }
        serverThread.start()

        try {
            val targetUrl = "http://127.0.0.1:$serverPort/test_502"
            val res = XrayRealDelayTester.probeSingleProxy(
                cleanIp = "127.0.0.1",
                httpPort = serverPort,
                timeoutMs = 1500L,
                targetUrl = targetUrl
            )
            assertEquals("FAILED", res.status)
            assertEquals(502, res.httpCode)
            assertEquals("HTTP 502", res.realStatus)
            assertEquals(-1L, res.delayMs)
        } finally {
            server.close()
            serverThread.join(500)
        }
    }

    @Test
    fun testProbeSingleProxyUnreachablePortFailure() {
        val unusedPort = PortManager.getFreePort()
        val res = XrayRealDelayTester.probeSingleProxy(
            cleanIp = "127.0.0.1",
            httpPort = unusedPort,
            timeoutMs = 400L,
            targetUrl = "http://127.0.0.1:$unusedPort/generate_204"
        )
        assertEquals("FAILED", res.status)
        assertEquals(-1L, res.delayMs)
        assertNotNull(res.error)
    }

    // =========================================================================
    // 7. Binary Fallback & File System Resilience
    // =========================================================================

    @Test
    fun testIsXrayAvailableWhenPathIsDirectory() {
        val fakeLibDir = File(System.getProperty("java.io.tmpdir"), "fake_dir_${System.currentTimeMillis()}")
        fakeLibDir.mkdirs()
        val fakeBinaryDir = File(fakeLibDir, "libxray.so")
        fakeBinaryDir.mkdirs() // Directory named libxray.so!
        try {
            assertFalse("libxray.so must be a regular file, not a directory", XrayRealDelayTester.isXrayAvailable(fakeLibDir))
        } finally {
            fakeBinaryDir.delete()
            fakeLibDir.delete()
        }
    }

    @Test
    fun testBatchRealDelayEmptyIpsList() = runBlocking {
        val fakeLibDir = File(System.getProperty("java.io.tmpdir"), "fake_lib_${System.currentTimeMillis()}")
        fakeLibDir.mkdirs()
        val cacheDir = File(System.getProperty("java.io.tmpdir"), "fake_cache_${System.currentTimeMillis()}")
        cacheDir.mkdirs()
        try {
            val parsed = ParsedConfig(protocol = "vless", port = 443)
            val res = XrayRealDelayTester.testBatchRealDelay(
                nativeLibDir = fakeLibDir,
                cacheDir = cacheDir,
                parsed = parsed,
                cleanIps = emptyList()
            )
            assertTrue("Empty clean IPs list must return empty map", res.isEmpty())
        } finally {
            fakeLibDir.deleteRecursively()
            cacheDir.deleteRecursively()
        }
    }
}

package com.cftester.scanner

import com.cftester.scanner.core.model.ParsedConfig
import com.cftester.scanner.core.xray.PortManager
import com.cftester.scanner.core.xray.XrayRealDelayTester
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.net.ServerSocket

class XrayRealDelayTesterTest {

    @Test
    fun testPortManagerSinglePortValid() {
        val port = PortManager.getFreePort()
        assertTrue("Port must be in unprivileged dynamic range (1024..65535)", port in 1024..65535)
    }

    @Test
    fun testPortManagerBatchPortsUnique() {
        val count = 25
        val ports = PortManager.getFreePorts(count)
        assertEquals("Must allocate exact count requested", count, ports.size)
        val uniquePorts = ports.toSet()
        assertEquals("All allocated batch ports must be mutually unique", count, uniquePorts.size)
        assertTrue("All ports must be > 1024", ports.all { it in 1024..65535 })
    }

    @Test
    fun testPortManagerConcurrency() = runBlocking {
        val jobs = (1..10).map {
            async {
                PortManager.getFreePorts(5)
            }
        }
        val allPortLists = jobs.awaitAll()
        for (portList in allPortLists) {
            assertEquals(5, portList.size)
            assertEquals(5, portList.toSet().size)
        }
    }

    @Test
    fun testActivePortReadinessTimeoutOnClosedPort() = runBlocking {
        val unusedPort = PortManager.getFreePort()
        val t0 = System.currentTimeMillis()
        val isReady = XrayRealDelayTester.waitForPortReady(unusedPort, timeoutMs = 200L, pollIntervalMs = 25L)
        val elapsed = System.currentTimeMillis() - t0
        assertFalse("Closed port must return false on timeout", isReady)
        assertTrue("Elapsed time should respect timeoutMs", elapsed in 180..600)
    }

    @Test
    fun testActivePortReadinessSuccessOnBoundPort() = runBlocking {
        val server = ServerSocket(0)
        val port = server.localPort
        try {
            val isReady = XrayRealDelayTester.waitForPortReady(port, timeoutMs = 1000L, pollIntervalMs = 20L)
            assertTrue("Bound port must be detected as ready", isReady)
        } finally {
            server.close()
        }
    }

    @Test
    fun testSingleRealDelayMissingBinary() = runBlocking {
        val fakeLibDir = File(System.getProperty("java.io.tmpdir"), "fake_jni_${System.currentTimeMillis()}")
        fakeLibDir.mkdirs()
        val cacheDir = File(System.getProperty("java.io.tmpdir"), "cache_${System.currentTimeMillis()}")
        cacheDir.mkdirs()

        try {
            val parsed = ParsedConfig(protocol = "vless", address = "orig.domain.com", port = 443)
            val result = XrayRealDelayTester.testRealDelay(
                nativeLibDir = fakeLibDir,
                cacheDir = cacheDir,
                parsed = parsed,
                cleanIp = "104.16.24.1"
            )
            assertEquals("Missing binary must return -1L", -1L, result)

            val detailedResult = XrayRealDelayTester.testSingleRealDelay(
                nativeLibDir = fakeLibDir,
                cacheDir = cacheDir,
                parsed = parsed,
                cleanIp = "104.16.24.1"
            )
            assertEquals("ERROR", detailedResult.status)
            assertTrue(detailedResult.error?.contains("Xray binary not found") == true)
        } finally {
            fakeLibDir.deleteRecursively()
            cacheDir.deleteRecursively()
        }
    }

    @Test
    fun testBatchRealDelayMissingBinary() = runBlocking {
        val fakeLibDir = File(System.getProperty("java.io.tmpdir"), "fake_jni_${System.currentTimeMillis()}")
        fakeLibDir.mkdirs()
        val cacheDir = File(System.getProperty("java.io.tmpdir"), "cache_${System.currentTimeMillis()}")
        cacheDir.mkdirs()

        try {
            val parsed = ParsedConfig(protocol = "vless", address = "orig.domain.com", port = 443)
            val cleanIps = listOf("104.16.1.1", "104.16.1.2")
            val batchResults = XrayRealDelayTester.testBatchRealDelay(
                nativeLibDir = fakeLibDir,
                cacheDir = cacheDir,
                parsed = parsed,
                cleanIps = cleanIps
            )
            assertEquals(2, batchResults.size)
            assertTrue(batchResults.containsKey("104.16.1.1"))
            assertTrue(batchResults.containsKey("104.16.1.2"))
            assertEquals("ERROR", batchResults["104.16.1.1"]?.status)
            assertEquals("ERROR", batchResults["104.16.1.2"]?.status)
            assertTrue(batchResults["104.16.1.1"]?.error?.contains("Xray binary not found") == true)
        } finally {
            fakeLibDir.deleteRecursively()
            cacheDir.deleteRecursively()
        }
    }

    @Test
    fun testIsXrayAvailableCheck() {
        val fakeLibDir = File(System.getProperty("java.io.tmpdir"), "fake_jni_${System.currentTimeMillis()}")
        fakeLibDir.mkdirs()
        try {
            assertFalse(XrayRealDelayTester.isXrayAvailable(fakeLibDir))
            val dummySo = File(fakeLibDir, "libxray.so")
            dummySo.writeText("ELF dummy binary")
            assertTrue(XrayRealDelayTester.isXrayAvailable(fakeLibDir))
        } finally {
            fakeLibDir.deleteRecursively()
        }
    }

    @Test
    fun testProbeSingleProxyMockServer() {
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
                writer.write("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                writer.flush()
                socket.close()
            } catch (_: Exception) {}
        }
        serverThread.start()

        try {
            val targetUrl = "http://127.0.0.1:$serverPort/generate_204"
            val res = XrayRealDelayTester.probeSingleProxy(
                cleanIp = "127.0.0.1",
                httpPort = serverPort,
                timeoutMs = 1500L,
                targetUrl = targetUrl
            )
            assertEquals("SUCCESS", res.status)
            assertEquals(204, res.httpCode)
            assertTrue("Delay should be measured", res.delayMs >= 0)
        } finally {
            server.close()
            serverThread.join(500)
        }
    }
}

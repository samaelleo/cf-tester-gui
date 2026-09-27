package com.cftester.scanner

import com.cftester.scanner.core.engine.TesterEngine
import com.cftester.scanner.core.engine.VlessPacketBuilder
import com.cftester.scanner.core.engine.WebSocketFrameBuilder
import com.cftester.scanner.core.model.ScanResult
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.nio.ByteBuffer
import java.util.UUID

class TesterEngineTest {

    private lateinit var engine: TesterEngine

    @Before
    fun setUp() {
        engine = TesterEngine()
    }

    @Test
    fun testVlessPayloadConstruction() {
        val testUuid = "d342d11e-d424-4583-b36e-524ab1f0afa4"
        val payload = engine.buildVlessPayload(
            userUuid = testUuid,
            targetHost = "connectivitycheck.gstatic.com",
            targetPort = 80,
            httpPath = "/generate_204"
        )

        assertNotNull(payload)
        assertTrue(payload.size > 23)

        // Version: 0x00
        assertEquals(0x00.toByte(), payload[0])

        // UUID bytes (16 bytes)
        val u = UUID.fromString(testUuid)
        val expectedUuidBb = ByteBuffer.allocate(16)
        expectedUuidBb.putLong(u.mostSignificantBits)
        expectedUuidBb.putLong(u.leastSignificantBits)
        val expectedUuidBytes = expectedUuidBb.array()

        val actualUuidBytes = payload.copyOfRange(1, 17)
        assertArrayEquals(expectedUuidBytes, actualUuidBytes)

        // Addon length: 0x00
        assertEquals(0x00.toByte(), payload[17])

        // Command: 0x01 (TCP Connect)
        assertEquals(0x01.toByte(), payload[18])

        // Port 80 (big-endian: 0x00, 0x50)
        assertEquals(0x00.toByte(), payload[19])
        assertEquals(0x50.toByte(), payload[20])

        // Addr type: 0x02 (Domain)
        assertEquals(0x02.toByte(), payload[21])

        // Addr len
        val host = "connectivitycheck.gstatic.com"
        assertEquals(host.length.toByte(), payload[22])

        // Host bytes
        val hostBytes = payload.copyOfRange(23, 23 + host.length)
        assertEquals(host, String(hostBytes, Charsets.US_ASCII))

        // HTTP payload
        val httpPart = String(payload.copyOfRange(23 + host.length, payload.size), Charsets.US_ASCII)
        assertTrue(httpPart.startsWith("GET /generate_204 HTTP/1.1\r\n"))
        assertTrue(httpPart.contains("Host: connectivitycheck.gstatic.com"))
    }

    @Test
    fun testVlessPayloadRandomUuidFallback() {
        // Invalid UUID string should fallback without throwing exception
        val payload = engine.buildVlessPayload(userUuid = "not-a-valid-uuid")
        assertNotNull(payload)
        assertEquals(0x00.toByte(), payload[0])
        assertEquals(0x01.toByte(), payload[18])
    }

    @Test
    fun testWebSocketFrameMasking() {
        val testData = "Hello WebSocket Google 204 Tunnel".toByteArray(Charsets.UTF_8)
        val frame = engine.buildWsFrame(testData)

        assertNotNull(frame)
        assertTrue(frame.size >= 2 + 4 + testData.size)

        // First byte: Opcode 0x82 (FIN + Binary frame)
        assertEquals(0x82.toByte(), frame[0])

        // Second byte: Mask bit 0x80 | length
        val secondByte = frame[1].toInt() and 0xFF
        assertTrue((secondByte and 0x80) != 0) // Mask bit is set
        val len = secondByte and 0x7F
        assertEquals(testData.size, len)

        // 4-byte mask key starts at index 2
        val maskKey = frame.copyOfRange(2, 6)
        assertEquals(4, maskKey.size)

        // Masked payload starts at index 6
        val maskedPayload = frame.copyOfRange(6, 6 + testData.size)

        // Unmask and verify payload integrity
        val unmasked = ByteArray(testData.size)
        for (i in testData.indices) {
            unmasked[i] = (maskedPayload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
        }
        assertArrayEquals(testData, unmasked)
    }

    @Test
    fun testEngineControls() {
        assertFalse(engine.isRunning.value)
        assertFalse(engine.isPaused.value)

        engine.pause()
        assertTrue(engine.isPaused.value)

        engine.resume()
        assertFalse(engine.isPaused.value)

        engine.stop()
        assertFalse(engine.isRunning.value)
        assertFalse(engine.isPaused.value)
        assertTrue(engine._cancelRequested.get())
    }

    @Test
    fun testDynamicLatencySorting() {
        val r1 = ScanResult(ip = "104.16.1.1", status = "SUCCESS", googleLatencyMs = 210f)
        val r2 = ScanResult(ip = "104.16.1.2", status = "SUCCESS", googleLatencyMs = 65f)
        val r3 = ScanResult(ip = "104.16.1.3", status = "SUCCESS", googleLatencyMs = 140f)

        val list = mutableListOf(r1, r2, r3)
        list.sortBy { if (it.googleLatencyMs > 0) it.googleLatencyMs else 99999f }

        assertEquals("104.16.1.2", list[0].ip)
        assertEquals(65f, list[0].googleLatencyMs, 0.01f)
        assertEquals("104.16.1.3", list[1].ip)
        assertEquals(140f, list[1].googleLatencyMs, 0.01f)
        assertEquals("104.16.1.1", list[2].ip)
        assertEquals(210f, list[2].googleLatencyMs, 0.01f)
    }
}

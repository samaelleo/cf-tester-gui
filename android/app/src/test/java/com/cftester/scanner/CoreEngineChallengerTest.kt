package com.cftester.scanner

import com.cftester.scanner.core.bgp.SubnetCalculator
import com.cftester.scanner.core.engine.VlessPacketBuilder
import com.cftester.scanner.core.engine.WebSocketFrameBuilder
import com.cftester.scanner.core.model.SamplingMode
import com.cftester.scanner.core.parser.ConfigParser
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.util.Base64
import java.util.UUID

class CoreEngineChallengerTest {

    // =========================================================================
    // 1. VLESS Binary Payload RFC Structure Verification
    // =========================================================================
    @Test
    fun testVlessBinaryPayloadRfcStructure() {
        val testUuid = "27848739-7e62-4138-9fd3-098a63964739"
        val domain = "connectivitycheck.gstatic.com"
        val port = 80
        val path = "/generate_204"

        val payload = VlessPacketBuilder.build(
            userUuid = testUuid,
            targetHost = domain,
            targetPort = port,
            httpPath = path
        )

        assertNotNull(payload)

        // RFC / Xray VLESS Request Protocol Structure:
        // 1. Version: 0x00 (1 byte)
        assertEquals("VLESS Version byte must be 0x00", 0x00.toByte(), payload[0])

        // 2. UUID: 16 bytes (bytes 1..16)
        val u = UUID.fromString(testUuid)
        val expectedUuid = ByteBuffer.allocate(16).apply {
            putLong(u.mostSignificantBits)
            putLong(u.leastSignificantBits)
        }.array()
        val actualUuid = payload.copyOfRange(1, 17)
        assertArrayEquals("UUID bytes must match RFC binary representation", expectedUuid, actualUuid)

        // 3. Addon length: 0x00 (byte 17)
        assertEquals("VLESS Addon length must be 0x00", 0x00.toByte(), payload[17])

        // 4. Command: 0x01 (TCP Connect) (byte 18)
        assertEquals("VLESS Command must be 0x01 (TCP Connect)", 0x01.toByte(), payload[18])

        // 5. Target Port: 2 bytes Big-Endian (bytes 19..20)
        val portBb = ByteBuffer.wrap(payload, 19, 2)
        val actualPort = portBb.short.toInt() and 0xFFFF
        assertEquals("VLESS Target port must match Big-Endian 80", 80, actualPort)

        // 6. Address Type: 0x02 (Domain Name) (byte 21)
        assertEquals("VLESS Address type must be 0x02 (Domain)", 0x02.toByte(), payload[21])

        // 7. Address Length: 1 byte (byte 22)
        val actualDomainLen = payload[22].toInt() and 0xFF
        assertEquals("Domain length byte must match string length", domain.length, actualDomainLen)

        // 8. Address bytes (bytes 23 .. 23 + domainLen - 1)
        val actualDomain = String(payload.copyOfRange(23, 23 + actualDomainLen), Charsets.US_ASCII)
        assertEquals("Domain bytes must match ASCII target host", domain, actualDomain)

        // 9. Payload bytes (HTTP request)
        val httpOffset = 23 + actualDomainLen
        val httpPart = String(payload.copyOfRange(httpOffset, payload.size), Charsets.US_ASCII)
        assertTrue("Payload must start with HTTP GET request", httpPart.startsWith("GET $path HTTP/1.1\r\n"))
        assertTrue("Payload must contain Host header", httpPart.contains("Host: $domain\r\n"))
        assertTrue("Payload must end with double CRLF", httpPart.endsWith("\r\n\r\n"))

        // Test custom ports (e.g. 443, 8443)
        val payload443 = VlessPacketBuilder.build(testUuid, domain, 443, path)
        val port443Bb = ByteBuffer.wrap(payload443, 19, 2)
        assertEquals(443, port443Bb.short.toInt() and 0xFFFF)

        val payload8443 = VlessPacketBuilder.build(testUuid, domain, 8443, path)
        val port8443Bb = ByteBuffer.wrap(payload8443, 19, 2)
        assertEquals(8443, port8443Bb.short.toInt() and 0xFFFF)

        // Test invalid UUID fallback (must not throw, returns 16 random bytes)
        val payloadInvalidUuid = VlessPacketBuilder.build("malformed-uuid-string", domain, 80, path)
        assertEquals(0x00.toByte(), payloadInvalidUuid[0])
        assertEquals(0x01.toByte(), payloadInvalidUuid[18])
        assertEquals(payload.size, payloadInvalidUuid.size)
    }

    // =========================================================================
    // 2. RFC 6455 WebSocket Binary Frame Masking Verification
    // =========================================================================
    @Test
    fun testWebSocketFrameMaskingRfc6455() {
        // Case A: Small payload (<= 125 bytes)
        val smallPayload = "VLESS WebSocket Probe Payload".toByteArray(Charsets.UTF_8)
        val smallFrame = WebSocketFrameBuilder.buildBinaryFrame(smallPayload)

        // Opcode 0x82: FIN bit (0x80) | Binary opcode (0x02)
        assertEquals(0x82.toByte(), smallFrame[0])

        // Byte 1: Mask bit (0x80) | Length (<= 125)
        val smallSecondByte = smallFrame[1].toInt() and 0xFF
        assertTrue("Mask bit MUST be set (0x80) for client frames", (smallSecondByte and 0x80) != 0)
        assertEquals("Payload length must match in 7-bit length field", smallPayload.size, smallSecondByte and 0x7F)

        // 4-byte mask key starts at index 2
        val smallMaskKey = smallFrame.copyOfRange(2, 6)
        assertEquals(4, smallMaskKey.size)

        // Unmask XOR and verify integrity
        val smallUnmasked = ByteArray(smallPayload.size)
        for (i in smallPayload.indices) {
            smallUnmasked[i] = (smallFrame[6 + i].toInt() xor smallMaskKey[i % 4].toInt()).toByte()
        }
        assertArrayEquals("Unmasked payload must match original small payload exactly", smallPayload, smallUnmasked)

        // Case B: Boundary 125 bytes payload
        val p125 = ByteArray(125) { (it % 256).toByte() }
        val frame125 = WebSocketFrameBuilder.buildBinaryFrame(p125)
        assertEquals(0x82.toByte(), frame125[0])
        assertEquals((0x80 or 125).toByte(), frame125[1])
        assertEquals(2 + 4 + 125, frame125.size)

        val maskKey125 = frame125.copyOfRange(2, 6)
        val unmasked125 = ByteArray(125)
        for (i in 0 until 125) {
            unmasked125[i] = (frame125[6 + i].toInt() xor maskKey125[i % 4].toInt()).toByte()
        }
        assertArrayEquals(p125, unmasked125)

        // Case C: Boundary 126 bytes payload (triggers 16-bit extended length)
        val p126 = ByteArray(126) { (it % 256).toByte() }
        val frame126 = WebSocketFrameBuilder.buildBinaryFrame(p126)
        assertEquals(0x82.toByte(), frame126[0])
        assertEquals((0x80 or 126).toByte(), frame126[1])

        // 2-byte extended length
        val extLen126 = ByteBuffer.wrap(frame126, 2, 2).short.toInt() and 0xFFFF
        assertEquals(126, extLen126)

        // Mask key starts at index 4
        val maskKey126 = frame126.copyOfRange(4, 8)
        assertEquals(4, maskKey126.size)

        // Unmask
        val unmasked126 = ByteArray(126)
        for (i in 0 until 126) {
            unmasked126[i] = (frame126[8 + i].toInt() xor maskKey126[i % 4].toInt()).toByte()
        }
        assertArrayEquals(p126, unmasked126)

        // Case D: Medium payload (1000 bytes)
        val p1000 = ByteArray(1000) { (it * 7 % 256).toByte() }
        val frame1000 = WebSocketFrameBuilder.buildBinaryFrame(p1000)
        assertEquals(0x82.toByte(), frame1000[0])
        assertEquals((0x80 or 126).toByte(), frame1000[1])
        val extLen1000 = ByteBuffer.wrap(frame1000, 2, 2).short.toInt() and 0xFFFF
        assertEquals(1000, extLen1000)

        val maskKey1000 = frame1000.copyOfRange(4, 8)
        val unmasked1000 = ByteArray(1000)
        for (i in 0 until 1000) {
            unmasked1000[i] = (frame1000[8 + i].toInt() xor maskKey1000[i % 4].toInt()).toByte()
        }
        assertArrayEquals(p1000, unmasked1000)
    }

    // =========================================================================
    // 3. ConfigParser Edge Cases
    // =========================================================================
    @Test
    fun testConfigParserPostQuantumAndXhttpExtra() {
        val rawPqUri = (
            "vless://937afff8-7513-4078-a759-b884b6c2d2ef@203.23.106.70:8443" +
            "?encryption=mlkem768x25519plus.xorpub.0rtt.Hfz68R2EM_t2U26EoytKVZZv3I2kxQApYvNh2LXEASg" +
            "&security=tls&sni=cf2.persiana.garden&fp=chrome&alpn=h2%2Chttp%2F1.1" +
            "&type=xhttp&host=cf.persiana.garden&path=%2Fcustom-path&mode=packet-up" +
            "&extra=%7B%22mode%22%3A%22packet-up%22%2C%22path%22%3A%22%2Fcustom-path%22%7D#PQ-Test"
        )
        val parsed = ConfigParser.parse(rawPqUri)
        assertEquals("vless", parsed.protocol)
        assertEquals("xhttp", parsed.transport)
        assertTrue("Must parse Post-Quantum mlkem768 parameter", parsed.encryption.contains("mlkem768"))
        assertEquals("packet-up", parsed.mode)
        assertEquals("/custom-path", parsed.path)
        assertEquals("cf.persiana.garden", parsed.host)
        assertEquals("cf2.persiana.garden", parsed.sni)

        // Verify extra JSON was parsed into map
        assertEquals("packet-up", parsed.extra["mode"])
        assertEquals("/custom-path", parsed.extra["path"])

        // Generate modified link and ensure PQ encryption is preserved
        val modLink = ConfigParser.generateModifiedLink(parsed, "104.16.24.1", "PQ-OK")
        assertTrue(modLink.contains("encryption=mlkem768"))
        assertTrue(modLink.contains("type=xhttp"))
        assertTrue(modLink.contains("@104.16.24.1:8443"))
    }

    @Test
    fun testConfigParserVmessBase64PaddingVariants() {
        val baseJson = """{"v":"2","ps":"PaddingNode","add":"orig.com","port":"443","id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","net":"ws","path":"/","tls":"tls"}"""
        val rawB64 = Base64.getEncoder().encodeToString(baseJson.toByteArray(Charsets.UTF_8))

        // Variant 1: Exact standard Base64 (with padding if present)
        val p1 = ConfigParser.parse("vmess://$rawB64")
        assertEquals("vmess", p1.protocol)
        assertEquals("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", p1.uuid)

        // Variant 2: Unpadded Base64 (stripped '=')
        val unpaddedB64 = rawB64.trimEnd('=')
        val p2 = ConfigParser.parse("vmess://$unpaddedB64")
        assertEquals("vmess", p2.protocol)
        assertEquals("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", p2.uuid)

        // Variant 3: URL-safe Base64 (with '-' and '_')
        val urlSafeB64 = rawB64.replace('+', '-').replace('/', '_')
        val p3 = ConfigParser.parse("vmess://$urlSafeB64")
        assertEquals("vmess", p3.protocol)
        assertEquals("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", p3.uuid)
    }

    @Test
    fun testConfigParserTrojanPasswordSpecialChars() {
        // Password with special characters: p@ss:word!#$
        val rawUri = "trojan://p%40ss%3Aword%21%23%24@trojan.node.net:443?security=tls&sni=trojan.node.net&type=ws&path=%2Fws#Special%20Tag"
        val parsed = ConfigParser.parse(rawUri)
        assertEquals("trojan", parsed.protocol)
        // userInfo contains the raw URL-encoded password
        assertTrue(parsed.uuid.isNotEmpty())
        assertEquals("trojan.node.net", parsed.address)
        assertEquals(443, parsed.port)

        val modLink = ConfigParser.generateModifiedLink(parsed, "104.16.24.1")
        assertTrue(modLink.startsWith("trojan://${parsed.uuid}@104.16.24.1:443"))
    }

    @Test
    fun testConfigParserShadowsocksVariants() {
        val methodPass = "chacha20-ietf-poly1305:mySecurePassword123"
        val b64Auth = Base64.getEncoder().encodeToString(methodPass.toByteArray(Charsets.UTF_8))

        // SIP002: ss://base64(method:pass)@host:port#tag
        val sip002Uri = "ss://$b64Auth@edge.example.com:8443#SIP002-Tag"
        val pSip002 = ConfigParser.parse(sip002Uri)
        assertEquals("ss", pSip002.protocol)
        assertEquals(methodPass, pSip002.uuid)
        assertEquals("edge.example.com", pSip002.address)
        assertEquals(8443, pSip002.port)
        assertEquals("SIP002-Tag", pSip002.tag)

        // Legacy: ss://base64(method:pass@host:port)#tag
        val legacyPayload = "$methodPass@edge.example.com:8443"
        val b64Legacy = Base64.getEncoder().encodeToString(legacyPayload.toByteArray(Charsets.UTF_8))
        val legacyUri = "ss://$b64Legacy#Legacy-Tag"
        val pLegacy = ConfigParser.parse(legacyUri)
        assertEquals("ss", pLegacy.protocol)
        assertEquals(methodPass, pLegacy.uuid)
        assertEquals("edge.example.com", pLegacy.address)
        assertEquals(8443, pLegacy.port)
        assertEquals("Legacy-Tag", pLegacy.tag)
    }

    // =========================================================================
    // 4. IPv6 Bracket Formatting in URIs vs Unbracketed in VMess JSON
    // =========================================================================
    @Test
    fun testIpv6BracketFormattingVsVmessUnbracketed() {
        val vlessSample = "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@myworker.workers.dev:443?type=ws&security=tls#VLESS"
        val trojanSample = "trojan://mypass123@trojan.workers.dev:443?type=ws&security=tls#Trojan"
        val ssSample = "ss://aes-128-gcm:pass@orig.domain.com:443#SS"
        val vmessSample = "vmess://" + Base64.getEncoder().encodeToString(
            """{"v":"2","ps":"VMess","add":"orig.com","port":"443","id":"11111111-2222-3333-4444-555555555555","net":"ws","tls":"tls"}""".toByteArray()
        )

        val cleanIpv6Bare = "2606:4700::1"
        val cleanIpv6WithBrackets = "[2606:4700::1]"

        // 1. VLESS: Must be bracketed RFC 3986 in authority
        val pVless = ConfigParser.parse(vlessSample)
        val modVless1 = ConfigParser.generateModifiedLink(pVless, cleanIpv6Bare)
        assertTrue("VLESS modified link must contain bracketed IPv6", modVless1.contains("@[2606:4700::1]:443"))
        assertFalse("Must not have double brackets", modVless1.contains("[["))

        val modVless2 = ConfigParser.generateModifiedLink(pVless, cleanIpv6WithBrackets)
        assertTrue("VLESS modified link must safely handle bracketed IPv6 input", modVless2.contains("@[2606:4700::1]:443"))
        assertFalse("Must not have double brackets", modVless2.contains("[["))

        // 2. Trojan: Must be bracketed
        val pTrojan = ConfigParser.parse(trojanSample)
        val modTrojan = ConfigParser.generateModifiedLink(pTrojan, cleanIpv6Bare)
        assertTrue("Trojan modified link must contain bracketed IPv6", modTrojan.contains("@[2606:4700::1]:443"))

        // 3. Shadowsocks: Must be bracketed
        val pSs = ConfigParser.parse(ssSample)
        val modSs = ConfigParser.generateModifiedLink(pSs, cleanIpv6Bare)
        assertTrue("Shadowsocks modified link must contain bracketed IPv6", modSs.contains("@[2606:4700::1]:443"))

        // 4. VMess JSON: "add" field MUST BE UNBRACKETED per V2Ray VMess standard
        val pVmess = ConfigParser.parse(vmessSample)
        val modVmessBare = ConfigParser.generateModifiedLink(pVmess, cleanIpv6Bare)
        val b64PayloadBare = modVmessBare.removePrefix("vmess://")
        val decodedJsonBare = String(Base64.getDecoder().decode(b64PayloadBare), Charsets.UTF_8)
        val jsonBare = JSONObject(decodedJsonBare)
        assertEquals("VMess JSON 'add' field MUST be unbracketed IPv6", "2606:4700::1", jsonBare.getString("add"))

        // Even if input has brackets "[2606:4700::1]", VMess JSON 'add' must be stripped to unbracketed
        val modVmessBracketed = ConfigParser.generateModifiedLink(pVmess, cleanIpv6WithBrackets)
        val b64PayloadBracketed = modVmessBracketed.removePrefix("vmess://")
        val decodedJsonBracketed = String(Base64.getDecoder().decode(b64PayloadBracketed), Charsets.UTF_8)
        val jsonBracketed = JSONObject(decodedJsonBracketed)
        assertEquals("VMess JSON 'add' field MUST strip brackets and remain unbracketed", "2606:4700::1", jsonBracketed.getString("add"))
    }

    // =========================================================================
    // 5. Candidate IP Generation with Extreme Inputs (/0, /32, /128, etc.)
    // =========================================================================
    @Test
    fun testCandidateGenerationExtremeInputs() {
        // A. IPv4 /32 single host boundary
        val c32 = SubnetCalculator.sampleSubnets(listOf("104.16.1.1/32"), SamplingMode.RANDOM, 5, 10)
        assertEquals(1, c32.size)
        assertEquals("104.16.1.1", c32[0].ip)
        assertFalse(c32[0].isIpv6)

        // B. IPv4 /31 two host boundary
        val c31 = SubnetCalculator.sampleSubnets(listOf("104.16.1.0/31"), SamplingMode.RANDOM, 5, 10)
        assertEquals(2, c31.size)
        val ips31 = c31.map { it.ip }.toSet()
        assertTrue(ips31.contains("104.16.1.0"))
        assertTrue(ips31.contains("104.16.1.1"))

        // C. IPv6 /128 single host boundary
        val c128 = SubnetCalculator.sampleSubnets(listOf("2606:4700::1/128"), SamplingMode.RANDOM, 5, 10)
        assertEquals(1, c128.size)
        assertTrue(c128[0].isIpv6)
        assertTrue(c128[0].ip.contains(":"))

        // D. IPv6 /127 two host boundary
        val c127 = SubnetCalculator.sampleSubnets(listOf("2606:4700::/127"), SamplingMode.RANDOM, 5, 10)
        assertEquals(2, c127.size)
        assertEquals(2, c127.map { it.ip }.toSet().size)

        // E. Extreme IPv6 /0 boundary (::/0)
        val cV6Zero = SubnetCalculator.sampleSubnets(listOf("::/0"), SamplingMode.RANDOM, 2, 5)
        assertNotNull(cV6Zero)
        assertTrue("::/0 must yield bounded samples without OOM", cV6Zero.size in 1..2)
        assertTrue(cV6Zero[0].isIpv6)

        // F. Extreme IPv4 /0 boundary (0.0.0.0/0)
        // Must not crash the application process
        val cV4Zero = SubnetCalculator.sampleSubnets(listOf("0.0.0.0/0"), SamplingMode.RANDOM, 2, 5)
        assertNotNull(cV4Zero)

        // G. Malformed inputs must not throw unhandled exceptions
        val malformed = listOf("104.16.1.1/33", "2606::/129", "invalid-ip/24", "", "not_a_subnet")
        val cMalformed = SubnetCalculator.sampleSubnets(malformed, SamplingMode.RANDOM, 2, 5)
        assertNotNull(cMalformed)
        assertTrue(cMalformed.isEmpty())
    }
}

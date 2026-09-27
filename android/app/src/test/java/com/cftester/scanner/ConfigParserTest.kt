package com.cftester.scanner

import com.cftester.scanner.core.parser.ConfigParser
import org.junit.Assert.*
import org.junit.Test
import java.net.URLDecoder
import java.util.Base64

class ConfigParserTest {

    private val sampleVlessWs = (
        "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@myworker.workers.dev:443" +
        "?type=ws&security=tls&path=%2F%3Fed%3D2560&host=myworker.workers.dev" +
        "&sni=myworker.workers.dev&fp=chrome#VLESS-WS-Node"
    )

    private val sampleVlessXhttpPq = (
        "vless://937afff8-7513-4078-a759-b884b6c2d2ef@203.23.106.70:8443" +
        "?encryption=mlkem768x25519plus.xorpub.0rtt.Hfz68R2EM_t2U26EoytKVZZv3I2kxQApYvNh2LXEASg" +
        "&security=tls&sni=cf2.persiana.garden&fp=chrome&alpn=h2%2Chttp%2F1.1&insecure=0" +
        "&type=xhttp&host=cf.persiana.garden&path=api%2Fv1%2Ftelemetry%2Fmetrics&mode=packet-up" +
        "&extra=%7B%22headers%22%3A%7B%22Accept-Encoding%22%3A%22gzip%22%7D%2C%22mode%22%3A%22packet-up%22%7D#PQ-Node"
    )

    private val sampleTrojan = "trojan://mypassword123@trojan.domain.com:443?security=tls&sni=trojan.domain.com&type=ws&path=%2Ftr#TrojanTest"

    private val sampleSsPlain = "ss://aes-256-gcm:mySecretPass123@orig.domain.com:8443#SS-Plain-Node"

    private val sampleSsSip002 = "ss://" + Base64.getEncoder().encodeToString("aes-256-gcm:mySecretPass123".toByteArray()) + "@orig.domain.com:8443#SS-SIP002-Node"

    private val sampleSsLegacy = "ss://" + Base64.getEncoder().encodeToString("aes-256-gcm:mySecretPass123@orig.domain.com:8443".toByteArray()) + "#SS-Legacy-Node"

    @Test
    fun testParseVlessWs() {
        val parsed = ConfigParser.parse(sampleVlessWs)
        assertEquals("vless", parsed.protocol)
        assertEquals("d342d11e-d424-4583-b36e-524ab1f0afa4", parsed.uuid)
        assertEquals("myworker.workers.dev", parsed.address)
        assertEquals(443, parsed.port)
        assertEquals("ws", parsed.transport)
        assertEquals("tls", parsed.security)
        assertEquals("myworker.workers.dev", parsed.sni)
        assertEquals("myworker.workers.dev", parsed.host)
        assertEquals("chrome", parsed.fingerprint)
        assertEquals("VLESS-WS-Node", parsed.tag)
    }

    @Test
    fun testParseVlessPostQuantumAndXhttp() {
        val parsed = ConfigParser.parse(sampleVlessXhttpPq)
        assertEquals("vless", parsed.protocol)
        assertEquals("xhttp", parsed.transport)
        assertEquals("tls", parsed.security)
        assertTrue(parsed.encryption.contains("mlkem768"))
        assertEquals("packet-up", parsed.mode)
        assertEquals("cf.persiana.garden", parsed.host)
        assertEquals("cf2.persiana.garden", parsed.sni)
        assertTrue(parsed.extra.containsKey("headers"))

        // Modified link generation
        val modLink = ConfigParser.generateModifiedLink(parsed, "104.16.24.1", "120ms")
        assertTrue(modLink.startsWith("vless://"))
        assertTrue(modLink.contains("@104.16.24.1:8443"))
        assertTrue(modLink.contains("encryption=mlkem768"))
        assertTrue(modLink.contains("type=xhttp"))
        val decodedTag = URLDecoder.decode(modLink.substringAfter("#"), "UTF-8")
        assertTrue(decodedTag.contains("CF:104.16.24.1 [120ms]"))
    }

    @Test
    fun testVlessModifiedLinkIpv6Brackets() {
        val parsed = ConfigParser.parse(sampleVlessWs)
        val modLink = ConfigParser.generateModifiedLink(parsed, "2606:4700::1", "45ms")
        assertTrue(modLink.contains("@[2606:4700::1]:443"))
    }

    @Test
    fun testParseVmessBase64Json() {
        val vmessJson = """{"v":"2","ps":"VMess-Test","add":"orig.domain.com","port":"443","id":"11111111-2222-3333-4444-555555555555","net":"ws","type":"none","host":"orig.domain.com","path":"/vmessws","tls":"tls","sni":"orig.domain.com"}"""
        val rawLink = "vmess://" + Base64.getEncoder().encodeToString(vmessJson.toByteArray())
        val parsed = ConfigParser.parse(rawLink)

        assertEquals("vmess", parsed.protocol)
        assertEquals("orig.domain.com", parsed.address)
        assertEquals(443, parsed.port)
        assertEquals("11111111-2222-3333-4444-555555555555", parsed.uuid)
        assertEquals("ws", parsed.transport)
        assertEquals("tls", parsed.security)

        val modLink = ConfigParser.generateModifiedLink(parsed, "104.16.24.1", "88ms")
        assertTrue(modLink.startsWith("vmess://"))
        val b64Payload = modLink.removePrefix("vmess://")
        val decoded = String(Base64.getDecoder().decode(b64Payload), Charsets.UTF_8)
        assertTrue(decoded.contains("\"add\":\"104.16.24.1\""))
        assertTrue(decoded.contains("CF:104.16.24.1"))
    }

    @Test
    fun testParseTrojan() {
        val parsed = ConfigParser.parse(sampleTrojan)
        assertEquals("trojan", parsed.protocol)
        assertEquals("mypassword123", parsed.uuid)
        assertEquals("trojan.domain.com", parsed.address)
        assertEquals(443, parsed.port)
        assertEquals("ws", parsed.transport)
        assertEquals("tls", parsed.security)
        assertEquals("TrojanTest", parsed.tag)

        val modLink = ConfigParser.generateModifiedLink(parsed, "162.158.0.1", "30ms")
        assertTrue(modLink.startsWith("trojan://mypassword123@162.158.0.1:443"))
    }

    @Test
    fun testParseShadowsocks() {
        // Plain
        val parsedPlain = ConfigParser.parse(sampleSsPlain)
        assertEquals("ss", parsedPlain.protocol)
        assertEquals("aes-256-gcm:mySecretPass123", parsedPlain.uuid)
        assertEquals("orig.domain.com", parsedPlain.address)
        assertEquals(8443, parsedPlain.port)

        // SIP002
        val parsedSip002 = ConfigParser.parse(sampleSsSip002)
        assertEquals("ss", parsedSip002.protocol)
        assertEquals("aes-256-gcm:mySecretPass123", parsedSip002.uuid)
        assertEquals("orig.domain.com", parsedSip002.address)
        assertEquals(8443, parsedSip002.port)

        // Legacy Base64
        val parsedLegacy = ConfigParser.parse(sampleSsLegacy)
        assertEquals("ss", parsedLegacy.protocol)
        assertEquals("aes-256-gcm:mySecretPass123", parsedLegacy.uuid)
        assertEquals("orig.domain.com", parsedLegacy.address)
        assertEquals(8443, parsedLegacy.port)

        // Regenerate link
        val modLink = ConfigParser.generateModifiedLink(parsedSip002, "104.16.24.1", "55ms")
        assertTrue(modLink.startsWith("ss://"))
        assertTrue(modLink.contains("@104.16.24.1:8443"))
    }

    @Test
    fun testParseGenericOrDirect() {
        val direct = "cf-direct.cloudflare.com:8443/cdn-cgi/trace"
        val parsed = ConfigParser.parse(direct)
        assertEquals("direct", parsed.protocol)
        assertEquals("cf-direct.cloudflare.com", parsed.address)
        assertEquals(8443, parsed.port)
        assertEquals("/cdn-cgi/trace", parsed.path)

        // Bare domain without port
        val bare = "cloudflare.com/cdn-cgi/trace"
        val parsedBare = ConfigParser.parse(bare)
        assertEquals(443, parsedBare.port)
        assertEquals("cloudflare.com", parsedBare.address)
        assertEquals("/cdn-cgi/trace", parsedBare.path)
    }

    @Test
    fun testBoundaryEmptyAndCorruptInput() {
        val empty = ConfigParser.parse("   ")
        assertEquals("vless", empty.protocol)
        assertEquals("", empty.address)

        val corruptVmess = ConfigParser.parse("vmess://not_valid_base64")
        assertNotNull(corruptVmess)
    }
}

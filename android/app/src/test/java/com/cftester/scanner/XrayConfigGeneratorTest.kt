package com.cftester.scanner

import com.cftester.scanner.core.parser.ConfigParser
import com.cftester.scanner.core.xray.XrayConfigGenerator
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class XrayConfigGeneratorTest {

    @Test
    fun testXrayJsonOutboundVless() {
        val link = (
            "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@myworker.workers.dev:443" +
            "?type=ws&security=tls&path=%2F%3Fed%3D2560&host=myworker.workers.dev" +
            "&sni=myworker.workers.dev&fp=chrome#VLESS-WS-Node"
        )
        val parsed = ConfigParser.parse(link)
        val jsonStr = XrayConfigGenerator.generateConfig(parsed, "104.16.24.1", 10808, 10809)

        val root = JSONObject(jsonStr)
        val outbounds = root.getJSONArray("outbounds")
        val proxy = outbounds.getJSONObject(0)

        assertEquals("proxy", proxy.getString("tag"))
        assertEquals("vless", proxy.getString("protocol"))

        val settings = proxy.getJSONObject("settings")
        val vnext = settings.getJSONArray("vnext").getJSONObject(0)
        assertEquals("104.16.24.1", vnext.getString("address"))
        assertEquals(443, vnext.getInt("port"))

        val user = vnext.getJSONArray("users").getJSONObject(0)
        assertEquals("d342d11e-d424-4583-b36e-524ab1f0afa4", user.getString("id"))

        val streamSettings = proxy.getJSONObject("streamSettings")
        assertEquals("ws", streamSettings.getString("network"))
        assertEquals("tls", streamSettings.getString("security"))
        assertEquals("myworker.workers.dev", streamSettings.getJSONObject("tlsSettings").getString("serverName"))
    }

    @Test
    fun testXrayJsonOutboundVmess() {
        val vmessJson = """{"v":"2","ps":"VMess-Node","add":"orig.com","port":443,"id":"11111111-2222-3333-4444-555555555555","net":"ws","path":"/vmess","tls":"tls","sni":"orig.com"}"""
        val link = "vmess://" + Base64.getEncoder().encodeToString(vmessJson.toByteArray())
        val parsed = ConfigParser.parse(link)

        val jsonStr = XrayConfigGenerator.generateConfig(parsed, "104.16.24.1", 10808, 10809)
        val root = JSONObject(jsonStr)
        val proxy = root.getJSONArray("outbounds").getJSONObject(0)

        assertEquals("vmess", proxy.getString("protocol"))
        val vnext = proxy.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
        assertEquals("104.16.24.1", vnext.getString("address"))
        assertEquals(443, vnext.getInt("port"))
        val user = vnext.getJSONArray("users").getJSONObject(0)
        assertEquals("11111111-2222-3333-4444-555555555555", user.getString("id"))
        assertEquals(0, user.getInt("alterId"))
        assertEquals("auto", user.getString("security"))
    }

    @Test
    fun testXrayJsonOutboundTrojan() {
        val link = "trojan://mypassword123@trojan.domain.com:443?security=tls&sni=trojan.domain.com&type=ws&path=%2Ftr#TrojanTest"
        val parsed = ConfigParser.parse(link)

        val jsonStr = XrayConfigGenerator.generateConfig(parsed, "104.16.24.1", 10808, 10809)
        val root = JSONObject(jsonStr)
        val proxy = root.getJSONArray("outbounds").getJSONObject(0)

        assertEquals("trojan", proxy.getString("protocol"))
        val server = proxy.getJSONObject("settings").getJSONArray("servers").getJSONObject(0)
        assertEquals("104.16.24.1", server.getString("address"))
        assertEquals(443, server.getInt("port"))
        assertEquals("mypassword123", server.getString("password"))
    }

    @Test
    fun testXrayJsonOutboundShadowsocks() {
        val rawCreds = "aes-256-gcm:mySecretPass123"
        val b64 = Base64.getEncoder().encodeToString(rawCreds.toByteArray())
        val link = "ss://$b64@orig.domain.com:8443#SS-Node"
        val parsed = ConfigParser.parse(link)

        val jsonStr = XrayConfigGenerator.generateConfig(parsed, "104.16.24.1", 10808, 10809)
        val root = JSONObject(jsonStr)
        val proxy = root.getJSONArray("outbounds").getJSONObject(0)

        assertEquals("shadowsocks", proxy.getString("protocol"))
        val server = proxy.getJSONObject("settings").getJSONArray("servers").getJSONObject(0)
        assertEquals("104.16.24.1", server.getString("address"))
        assertEquals(8443, server.getInt("port"))
        assertEquals("aes-256-gcm", server.getString("method"))
        assertEquals("mySecretPass123", server.getString("password"))
    }

    @Test
    fun testXrayJsonShadowsocksCredentialsVariants() {
        // SIP002 Base64
        val creds1 = XrayConfigGenerator.extractSsCreds(Base64.getEncoder().encodeToString("chacha20-ietf-poly1305:Pass123".toByteArray()))
        assertEquals("chacha20-ietf-poly1305", creds1.first)
        assertEquals("Pass123", creds1.second)

        // Plain method:password
        val creds2 = XrayConfigGenerator.extractSsCreds("2022-blake3-aes-128-gcm:MyPassword")
        assertEquals("2022-blake3-aes-128-gcm", creds2.first)
        assertEquals("MyPassword", creds2.second)

        // Legacy format method:password@host:port
        val creds3 = XrayConfigGenerator.extractSsCreds("aes-128-gcm:Pass@104.16.24.1:8443")
        assertEquals("aes-128-gcm", creds3.first)
        assertEquals("Pass", creds3.second)
    }

    @Test
    fun testXrayJsonTransportsAndReality() {
        // Reality + gRPC
        val realityGrpc = (
            "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@orig.com:443" +
            "?type=grpc&security=reality&pbk=fakePbkKey123&sid=1234abcd&spx=%2F&sni=orig.com&fp=chrome&path=my-grpc-service#RealityNode"
        )
        val parsed = ConfigParser.parse(realityGrpc)
        val jsonStr = XrayConfigGenerator.generateConfig(parsed, "104.16.24.1", 10808, 10809)

        val root = JSONObject(jsonStr)
        val streamSettings = root.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")

        assertEquals("grpc", streamSettings.getString("network"))
        assertEquals("reality", streamSettings.getString("security"))
        val realitySettings = streamSettings.getJSONObject("realitySettings")
        assertEquals("fakePbkKey123", realitySettings.getString("publicKey"))
        assertEquals("1234abcd", realitySettings.getString("shortId"))
        assertEquals("orig.com", realitySettings.getString("serverName"))

        val grpcSettings = streamSettings.getJSONObject("grpcSettings")
        assertEquals("my-grpc-service", grpcSettings.getString("serviceName"))
    }

    @Test
    fun testXrayJsonBatchConfigArbitraryPorts() {
        val link = "trojan://mypass123@trojan.domain.com:443?security=tls&sni=trojan.domain.com#Trojan"
        val parsed = ConfigParser.parse(link)

        val cleanIps = listOf("104.16.1.1", "104.16.1.2", "104.16.1.3")
        val ports = listOf(14521, 23891, 31204)
        val jsonStr = XrayConfigGenerator.generateBatchConfig(parsed, cleanIps, ports)

        val root = JSONObject(jsonStr)
        val inbounds = root.getJSONArray("inbounds")
        assertEquals(3, inbounds.length())
        assertEquals(14521, inbounds.getJSONObject(0).getInt("port"))
        assertEquals(23891, inbounds.getJSONObject(1).getInt("port"))
        assertEquals(31204, inbounds.getJSONObject(2).getInt("port"))

        val outbounds = root.getJSONArray("outbounds")
        assertEquals(4, outbounds.length()) // proxy-0, proxy-1, proxy-2, direct
        assertEquals("proxy-0", outbounds.getJSONObject(0).getString("tag"))
        assertEquals("direct", outbounds.getJSONObject(3).getString("tag"))

        val routing = root.getJSONObject("routing")
        assertEquals("AsIs", routing.getString("domainStrategy"))
        val rules = routing.getJSONArray("rules")
        assertEquals(3, rules.length())
        assertEquals("proxy-0", rules.getJSONObject(0).getString("outboundTag"))
        assertEquals("http-in-0", rules.getJSONObject(0).getJSONArray("inboundTag").getString(0))
    }

    @Test
    fun testXrayJsonBatchConfigLegacyOverload() {
        val link = "trojan://mypass123@trojan.domain.com:443?security=tls&sni=trojan.domain.com#Trojan"
        val parsed = ConfigParser.parse(link)

        val cleanIps = listOf("104.16.1.1", "104.16.1.2")
        val jsonStr = XrayConfigGenerator.generateBatchConfig(parsed, cleanIps, 10800, 10900)

        val root = JSONObject(jsonStr)
        val inbounds = root.getJSONArray("inbounds")
        assertEquals(2, inbounds.length())
        assertEquals(10800, inbounds.getJSONObject(0).getInt("port"))
        assertEquals(10801, inbounds.getJSONObject(1).getInt("port"))
    }

    @Test
    fun testXrayJsonIpv6AddressBracketStripping() {
        val link = "vless://uuid@orig.domain:443?type=ws&security=tls#VLESS"
        val parsed = ConfigParser.parse(link)
        val jsonStr = XrayConfigGenerator.generateConfig(parsed, "[2606:4700::1]", 10808, 10809)

        val root = JSONObject(jsonStr)
        val proxy = root.getJSONArray("outbounds").getJSONObject(0)
        val address = proxy.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address")
        assertEquals("Bracketed IPv6 input must be formatted without brackets in Xray outbound", "2606:4700::1", address)
    }
}

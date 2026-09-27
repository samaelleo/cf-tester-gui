package com.cftester.scanner.core.xray

import com.cftester.scanner.core.model.ParsedConfig
import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64

object XrayConfigGenerator {

    fun generateConfig(
        parsed: ParsedConfig,
        cleanIp: String,
        httpPort: Int = 10808,
        socksPort: Int = 10809
    ): String {
        val root = JSONObject()

        val logObj = JSONObject()
        logObj.put("loglevel", "warning")
        root.put("log", logObj)

        val inboundsArr = JSONArray()

        val httpInbound = JSONObject()
        httpInbound.put("tag", "http-in")
        httpInbound.put("port", httpPort)
        httpInbound.put("listen", "127.0.0.1")
        httpInbound.put("protocol", "http")
        httpInbound.put("settings", JSONObject().put("allowTransparent", false))
        inboundsArr.put(httpInbound)

        val socksInbound = JSONObject()
        socksInbound.put("tag", "socks-in")
        socksInbound.put("port", socksPort)
        socksInbound.put("listen", "127.0.0.1")
        socksInbound.put("protocol", "socks")
        val socksSettings = JSONObject()
        socksSettings.put("auth", "noauth")
        socksSettings.put("udp", true)
        socksInbound.put("settings", socksSettings)
        inboundsArr.put(socksInbound)

        root.put("inbounds", inboundsArr)

        val outboundsArr = JSONArray()
        val proxyOutbound = buildOutbound(parsed, cleanIp, "proxy")
        outboundsArr.put(proxyOutbound)

        val directOutbound = JSONObject()
        directOutbound.put("tag", "direct")
        directOutbound.put("protocol", "freedom")
        directOutbound.put("settings", JSONObject())
        outboundsArr.put(directOutbound)

        root.put("outbounds", outboundsArr)

        return root.toString(2)
    }

    /**
     * Primary multi-inbound batch config generator matching desktop core/xray_runner.py.
     * Takes an explicit list of dynamic free HTTP ports matching cleanIps 1:1.
     */
    fun generateBatchConfig(
        parsed: ParsedConfig,
        cleanIps: List<String>,
        inboundHttpPorts: List<Int>
    ): String {
        require(cleanIps.size == inboundHttpPorts.size) {
            "Mismatch between clean IPs count (${cleanIps.size}) and ports count (${inboundHttpPorts.size})"
        }

        val root = JSONObject()
        val logObj = JSONObject()
        logObj.put("loglevel", "warning")
        root.put("log", logObj)

        val inboundsArr = JSONArray()
        val outboundsArr = JSONArray()
        val rulesArr = JSONArray()

        cleanIps.forEachIndexed { index, rawIp ->
            val port = inboundHttpPorts[index]
            val inTag = "http-in-$index"
            val outTag = "proxy-$index"

            val httpInbound = JSONObject()
            httpInbound.put("tag", inTag)
            httpInbound.put("port", port)
            httpInbound.put("listen", "127.0.0.1")
            httpInbound.put("protocol", "http")
            httpInbound.put("settings", JSONObject().put("allowTransparent", false))
            inboundsArr.put(httpInbound)

            val proxyOutbound = buildOutbound(parsed, rawIp, outTag)
            outboundsArr.put(proxyOutbound)

            val rule = JSONObject()
            rule.put("type", "field")
            rule.put("inboundTag", JSONArray().put(inTag))
            rule.put("outboundTag", outTag)
            rulesArr.put(rule)
        }

        val directOutbound = JSONObject()
        directOutbound.put("tag", "direct")
        directOutbound.put("protocol", "freedom")
        directOutbound.put("settings", JSONObject())
        outboundsArr.put(directOutbound)

        root.put("inbounds", inboundsArr)
        root.put("outbounds", outboundsArr)

        val routingObj = JSONObject()
        routingObj.put("domainStrategy", "AsIs")
        routingObj.put("rules", rulesArr)
        root.put("routing", routingObj)

        return root.toString(2)
    }

    /**
     * Backward-compatible overload for legacy callers.
     */
    fun generateBatchConfig(
        parsed: ParsedConfig,
        cleanIps: List<String>,
        baseHttpPort: Int,
        @Suppress("UNUSED_PARAMETER") baseSocksPort: Int
    ): String {
        val ports = cleanIps.indices.map { baseHttpPort + it }
        return generateBatchConfig(parsed, cleanIps, ports)
    }

    fun buildOutbound(parsed: ParsedConfig, cleanIp: String, tag: String): JSONObject {
        val outbound = JSONObject()
        outbound.put("tag", tag)

        val formattedIp = cleanIp.trim().removeSurrounding("[", "]")

        when (parsed.protocol.lowercase()) {
            "vless" -> {
                outbound.put("protocol", "vless")
                val settings = JSONObject()
                val vnextArr = JSONArray()
                val serverObj = JSONObject()
                serverObj.put("address", formattedIp)
                serverObj.put("port", parsed.port)

                val usersArr = JSONArray()
                val userObj = JSONObject()
                userObj.put("id", parsed.uuid)
                userObj.put("encryption", if (parsed.encryption.isNotEmpty() && parsed.encryption != "none") parsed.encryption else "none")
                if (parsed.flow.isNotEmpty()) userObj.put("flow", parsed.flow)
                usersArr.put(userObj)
                serverObj.put("users", usersArr)
                vnextArr.put(serverObj)
                settings.put("vnext", vnextArr)
                outbound.put("settings", settings)
            }
            "vmess" -> {
                outbound.put("protocol", "vmess")
                val settings = JSONObject()
                val vnextArr = JSONArray()
                val serverObj = JSONObject()
                serverObj.put("address", formattedIp)
                serverObj.put("port", parsed.port)

                val usersArr = JSONArray()
                val userObj = JSONObject()
                userObj.put("id", parsed.uuid)
                userObj.put("alterId", 0)
                userObj.put("security", "auto")
                usersArr.put(userObj)
                serverObj.put("users", usersArr)
                vnextArr.put(serverObj)
                settings.put("vnext", vnextArr)
                outbound.put("settings", settings)
            }
            "trojan" -> {
                outbound.put("protocol", "trojan")
                val settings = JSONObject()
                val serversArr = JSONArray()
                val serverObj = JSONObject()
                serverObj.put("address", formattedIp)
                serverObj.put("port", parsed.port)
                serverObj.put("password", parsed.uuid)
                serversArr.put(serverObj)
                settings.put("servers", serversArr)
                outbound.put("settings", settings)
            }
            "ss", "shadowsocks" -> {
                outbound.put("protocol", "shadowsocks")
                val settings = JSONObject()
                val serversArr = JSONArray()
                val serverObj = JSONObject()
                serverObj.put("address", formattedIp)
                serverObj.put("port", parsed.port)

                val methodAndPass = extractSsCreds(parsed.uuid)
                serverObj.put("method", methodAndPass.first)
                serverObj.put("password", methodAndPass.second)
                serverObj.put("ota", false)
                serversArr.put(serverObj)
                settings.put("servers", serversArr)
                outbound.put("settings", settings)
            }
            else -> {
                outbound.put("protocol", "freedom")
                return outbound
            }
        }

        // StreamSettings
        val streamSettings = JSONObject()
        val transport = when (parsed.transport.lowercase()) {
            "ws" -> "ws"
            "grpc" -> "grpc"
            "httpupgrade" -> "httpupgrade"
            "xhttp", "splithttp" -> "xhttp"
            else -> "tcp"
        }
        streamSettings.put("network", transport)

        val origDomain = parsed.getSniOrHost()

        when (transport) {
            "ws" -> {
                val wsSettings = JSONObject()
                wsSettings.put("path", parsed.path.ifEmpty { "/" })
                val headers = JSONObject()
                headers.put("Host", parsed.host.ifEmpty { origDomain })
                wsSettings.put("headers", headers)
                streamSettings.put("wsSettings", wsSettings)
            }
            "xhttp" -> {
                val xhttpSettings = JSONObject()
                xhttpSettings.put("path", parsed.path.ifEmpty { "/" })
                xhttpSettings.put("host", parsed.host.ifEmpty { origDomain })
                if (parsed.mode.isNotEmpty()) xhttpSettings.put("mode", parsed.mode)
                if (parsed.extra.isNotEmpty()) {
                    val extraObj = JSONObject()
                    for ((k, v) in parsed.extra) {
                        extraObj.put(k, v)
                    }
                    xhttpSettings.put("extra", extraObj)
                }
                streamSettings.put("xhttpSettings", xhttpSettings)
            }
            "grpc" -> {
                val grpcSettings = JSONObject()
                grpcSettings.put("serviceName", parsed.path.trimStart('/'))
                grpcSettings.put("multiMode", true)
                streamSettings.put("grpcSettings", grpcSettings)
            }
            "httpupgrade" -> {
                val httpUpgradeSettings = JSONObject()
                httpUpgradeSettings.put("path", parsed.path.ifEmpty { "/" })
                httpUpgradeSettings.put("host", parsed.host.ifEmpty { origDomain })
                streamSettings.put("httpupgradeSettings", httpUpgradeSettings)
            }
        }

        val sec = parsed.security.lowercase()
        if (sec == "tls") {
            streamSettings.put("security", "tls")
            val tlsSettings = JSONObject()
            tlsSettings.put("serverName", parsed.sni.ifEmpty { origDomain })
            tlsSettings.put("allowInsecure", false)
            if (parsed.alpn.isNotEmpty()) {
                val alpnList = parsed.alpn.split(",").map { it.trim() }
                tlsSettings.put("alpn", JSONArray(alpnList))
            }
            if (parsed.fingerprint.isNotEmpty()) {
                tlsSettings.put("fingerprint", parsed.fingerprint)
            }
            streamSettings.put("tlsSettings", tlsSettings)
        } else if (sec == "reality") {
            streamSettings.put("security", "reality")
            val realitySettings = JSONObject()
            realitySettings.put("serverName", parsed.sni.ifEmpty { origDomain })
            if (parsed.fingerprint.isNotEmpty()) realitySettings.put("fingerprint", parsed.fingerprint)
            if (parsed.pbk.isNotEmpty()) realitySettings.put("publicKey", parsed.pbk)
            if (parsed.sid.isNotEmpty()) realitySettings.put("shortId", parsed.sid)
            if (parsed.spx.isNotEmpty()) realitySettings.put("spiderX", parsed.spx)
            streamSettings.put("realitySettings", realitySettings)
        } else {
            streamSettings.put("security", "none")
        }

        outbound.put("streamSettings", streamSettings)
        return outbound
    }

    fun extractSsCreds(userinfo: String): Pair<String, String> {
        val raw = userinfo.trim()
        if (raw.isEmpty()) return Pair("aes-256-gcm", "")

        // 1. If no colon in raw, attempt Base64 decode (SIP002 or legacy Base64)
        if (!raw.contains(":")) {
            try {
                var b64 = raw
                val pad = b64.length % 4
                if (pad != 0) b64 += "=".repeat(4 - pad)
                val decodedBytes = try {
                    Base64.getUrlDecoder().decode(b64)
                } catch (_: Exception) {
                    Base64.getDecoder().decode(b64)
                }
                var decodedStr = String(decodedBytes, Charsets.UTF_8)
                if (decodedStr.contains("@")) {
                    val atIdx = decodedStr.lastIndexOf("@")
                    val hp = decodedStr.substring(atIdx + 1)
                    if (hp.contains(":") && hp.substringAfterLast(":").all { it.isDigit() }) {
                        decodedStr = decodedStr.substring(0, atIdx)
                    }
                }
                if (decodedStr.contains(":")) {
                    val parts = decodedStr.split(":", limit = 2)
                    return Pair(parts[0].trim(), parts[1].trim())
                }
            } catch (_: Exception) {}
        }

        // 2. Check if legacy method:password@host:port format
        var target = raw
        if (target.contains("@")) {
            val atIdx = target.lastIndexOf("@")
            val hp = target.substring(atIdx + 1)
            if (hp.contains(":") && hp.substringAfterLast(":").all { it.isDigit() }) {
                target = target.substring(0, atIdx)
            }
        }

        // 3. Split plain method:password
        if (target.contains(":")) {
            val parts = target.split(":", limit = 2)
            return Pair(parts[0].trim(), parts[1].trim())
        }

        // 4. Fallback: treat raw as password with standard cipher
        return Pair("aes-256-gcm", target)
    }
}

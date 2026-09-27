package com.cftester.scanner.core.parser

import com.cftester.scanner.core.model.ParsedConfig
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.Base64
import java.util.regex.Pattern

object ConfigParser {

    fun parse(configStr: String?): ParsedConfig {
        val link = configStr?.trim() ?: ""
        if (link.isEmpty()) return ParsedConfig()

        return try {
            when {
                link.startsWith("vless://") -> parseVless(link)
                link.startsWith("vmess://") -> parseVmess(link)
                link.startsWith("trojan://") -> parseTrojan(link)
                link.startsWith("ss://") -> parseShadowsocks(link)
                else -> parseGenericOrDirect(link)
            }
        } catch (_: Exception) {
            ParsedConfig(rawLink = link)
        }
    }

    fun parseVless(link: String): ParsedConfig {
        return try {
            val uri = URI(link)
            val uuid = uri.userInfo ?: ""
            val address = uri.host ?: ""
            val port = if (uri.port > 0) uri.port else 443
            val rawTag = uri.fragment ?: "VLESS-Node"
            val tag = try { URLDecoder.decode(rawTag, "UTF-8") } catch (_: Exception) { rawTag }

            val queryMap = parseQuery(uri.rawQuery ?: "")

            val transport = (queryMap["type"] ?: queryMap["net"] ?: "ws").lowercase()
            val security = queryMap["security"] ?: "tls"
            var rawPath = queryMap["path"] ?: "/"
            try { rawPath = URLDecoder.decode(rawPath, "UTF-8") } catch (_: Exception) {}
            val path = if (rawPath.startsWith("/")) rawPath else "/$rawPath"

            var host = queryMap["host"] ?: ""
            var sni = queryMap["sni"] ?: ""
            val alpn = queryMap["alpn"] ?: ""
            val fp = queryMap["fp"] ?: "chrome"
            val flow = queryMap["flow"] ?: ""
            val encryption = queryMap["encryption"] ?: "none"
            val mode = queryMap["mode"] ?: ""
            val pbk = queryMap["pbk"] ?: ""
            val sid = queryMap["sid"] ?: ""
            val spx = queryMap["spx"] ?: ""

            val extraMap = mutableMapOf<String, Any>()
            val extraVal = queryMap["extra"]
            if (!extraVal.isNullOrEmpty()) {
                try {
                    val decodedJson = try { URLDecoder.decode(extraVal, "UTF-8") } catch (_: Exception) { extraVal }
                    val jsonObj = JSONObject(decodedJson)
                    val keys = jsonObj.keys()
                    while (keys.hasNext()) {
                        val k = keys.next()
                        val v = jsonObj.get(k)
                        if (v is JSONObject) {
                            val innerMap = mutableMapOf<String, Any>()
                            val innerKeys = v.keys()
                            while (innerKeys.hasNext()) {
                                val ik = innerKeys.next()
                                innerMap[ik] = v.get(ik)
                            }
                            extraMap[k] = innerMap
                        } else {
                            extraMap[k] = v
                        }
                    }
                } catch (_: Exception) {}
            }

            if (sni.isEmpty() && !isIp(address)) sni = address
            if (host.isEmpty() && !isIp(address)) host = address

            ParsedConfig(
                protocol = "vless",
                address = address,
                port = port,
                uuid = uuid,
                security = security,
                transport = transport,
                path = path,
                host = host,
                sni = sni,
                alpn = alpn,
                fingerprint = fp,
                flow = flow,
                pbk = pbk,
                sid = sid,
                spx = spx,
                encryption = encryption,
                mode = mode,
                tag = tag,
                rawLink = link,
                extra = extraMap,
                extraParams = queryMap
            )
        } catch (_: Exception) {
            ParsedConfig(rawLink = link)
        }
    }

    fun parseVmess(link: String): ParsedConfig {
        return try {
            var b64 = link.removePrefix("vmess://").trim()
            val pad = b64.length % 4
            if (pad != 0) b64 += "=".repeat(4 - pad)

            val decodedBytes = try {
                Base64.getUrlDecoder().decode(b64)
            } catch (_: Exception) {
                Base64.getDecoder().decode(b64)
            }
            val jsonStr = String(decodedBytes, Charsets.UTF_8)
            val json = JSONObject(jsonStr)

            val address = json.optString("add", "")
            val port = json.optInt("port", 443)
            val uuid = json.optString("id", "")
            val transport = json.optString("net", "ws").lowercase()
            var rawPath = json.optString("path", "/")
            if (!rawPath.startsWith("/")) rawPath = "/$rawPath"
            val path = rawPath

            var host = json.optString("host", "")
            var sni = json.optString("sni", "")
            val tlsVal = json.optString("tls", "tls")
            val security = if (tlsVal in listOf("tls", "1", "true")) "tls" else tlsVal
            val tag = json.optString("ps", "VMess-Node")

            if (sni.isEmpty() && !isIp(address)) sni = address
            if (host.isEmpty() && !isIp(address)) host = address

            val extraParams = mutableMapOf<String, String>()
            val keys = json.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                extraParams[k] = json.optString(k, "")
            }

            ParsedConfig(
                protocol = "vmess",
                address = address,
                port = port,
                uuid = uuid,
                security = security,
                transport = transport,
                path = path,
                host = host,
                sni = sni,
                tag = tag,
                rawLink = link,
                extraParams = extraParams
            )
        } catch (_: Exception) {
            ParsedConfig(rawLink = link)
        }
    }

    fun parseTrojan(link: String): ParsedConfig {
        return try {
            val uri = URI(link)
            val password = uri.userInfo ?: ""
            val address = uri.host ?: ""
            val port = if (uri.port > 0) uri.port else 443
            val rawTag = uri.fragment ?: "Trojan-Node"
            val tag = try { URLDecoder.decode(rawTag, "UTF-8") } catch (_: Exception) { rawTag }

            val queryMap = parseQuery(uri.rawQuery ?: "")

            val transport = queryMap["type"]?.lowercase() ?: "ws"
            val security = queryMap["security"] ?: "tls"
            var rawPath = queryMap["path"] ?: "/"
            try { rawPath = URLDecoder.decode(rawPath, "UTF-8") } catch (_: Exception) {}
            val path = if (rawPath.startsWith("/")) rawPath else "/$rawPath"

            var host = queryMap["host"] ?: ""
            var sni = queryMap["sni"] ?: ""
            val alpn = queryMap["alpn"] ?: ""
            val fp = queryMap["fp"] ?: "chrome"

            if (sni.isEmpty() && !isIp(address)) sni = address
            if (host.isEmpty() && !isIp(address)) host = address

            ParsedConfig(
                protocol = "trojan",
                address = address,
                port = port,
                uuid = password,
                security = security,
                transport = transport,
                path = path,
                host = host,
                sni = sni,
                alpn = alpn,
                fingerprint = fp,
                tag = tag,
                rawLink = link,
                extraParams = queryMap
            )
        } catch (_: Exception) {
            ParsedConfig(rawLink = link)
        }
    }

    fun parseShadowsocks(link: String): ParsedConfig {
        return try {
            val withoutScheme = link.removePrefix("ss://")
            val hashParts = withoutScheme.split("#", limit = 2)
            val netlocAndAuth = hashParts[0]
            val tag = if (hashParts.size > 1) {
                try { URLDecoder.decode(hashParts[1], "UTF-8") } catch (_: Exception) { hashParts[1] }
            } else "SS-Node"

            var address = ""
            var port = 443
            var password = ""

            if (netlocAndAuth.contains("@")) {
                val atParts = netlocAndAuth.split("@", limit = 2)
                val userInfo = atParts[0]
                val hostPort = atParts[1]

                // userInfo may be base64 encoded or plain method:password
                password = decodeSsUserInfo(userInfo)

                if (hostPort.startsWith("[") && hostPort.contains("]:")) {
                    val hpParts = hostPort.substring(1).split("]:", limit = 2)
                    address = hpParts[0]
                    port = hpParts[1].toIntOrNull() ?: 443
                } else if (hostPort.contains(":")) {
                    val lastColon = hostPort.lastIndexOf(":")
                    address = hostPort.substring(0, lastColon)
                    port = hostPort.substring(lastColon + 1).toIntOrNull() ?: 443
                } else {
                    address = hostPort
                }
            } else {
                // Legacy Base64: ss://base64(method:password@host:port)
                var b64 = netlocAndAuth
                val pad = b64.length % 4
                if (pad != 0) b64 += "=".repeat(4 - pad)

                try {
                    val decoded = String(
                        try { Base64.getUrlDecoder().decode(b64) } catch (_: Exception) { Base64.getDecoder().decode(b64) },
                        Charsets.UTF_8
                    )
                    if (decoded.contains("@")) {
                        val atIndex = decoded.lastIndexOf("@")
                        val userInfo = decoded.substring(0, atIndex)
                        val hostPort = decoded.substring(atIndex + 1)
                        password = userInfo

                        if (hostPort.startsWith("[") && hostPort.contains("]:")) {
                            val hpParts = hostPort.substring(1).split("]:", limit = 2)
                            address = hpParts[0]
                            port = hpParts[1].toIntOrNull() ?: 443
                        } else if (hostPort.contains(":")) {
                            val lastColon = hostPort.lastIndexOf(":")
                            address = hostPort.substring(0, lastColon)
                            port = hostPort.substring(lastColon + 1).toIntOrNull() ?: 443
                        } else {
                            address = hostPort
                        }
                    } else {
                        address = netlocAndAuth
                    }
                } catch (_: Exception) {
                    address = netlocAndAuth
                }
            }

            ParsedConfig(
                protocol = "ss",
                address = address,
                port = port,
                uuid = password,
                security = "none",
                transport = "tcp",
                tag = tag,
                rawLink = link
            )
        } catch (_: Exception) {
            ParsedConfig(rawLink = link)
        }
    }

    fun parseGenericOrDirect(text: String): ParsedConfig {
        var str = text.trim()
        var port = 443
        var host = str
        var path = "/"

        if (str.startsWith("[") && str.contains("]:")) {
            val parts = str.substring(1).split("]:", limit = 2)
            host = parts[0]
            val rest = parts[1]
            if (rest.contains("/")) {
                val slashParts = rest.split("/", limit = 2)
                port = slashParts[0].toIntOrNull() ?: 443
                path = "/" + slashParts[1]
            } else {
                port = rest.toIntOrNull() ?: 443
            }
        } else if (str.contains(":") && !str.startsWith("[")) {
            val colonCount = str.count { it == ':' }
            if (colonCount >= 2) {
                // Bare IPv6
                val slashParts = str.split("/", limit = 2)
                host = slashParts[0]
                if (slashParts.size > 1) path = "/" + slashParts[1]
            } else {
                val parts = str.split(":", limit = 2)
                host = parts[0]
                val rest = parts[1]
                if (rest.contains("/")) {
                    val slashParts = rest.split("/", limit = 2)
                    port = slashParts[0].toIntOrNull() ?: 443
                    path = "/" + slashParts[1]
                } else {
                    port = rest.toIntOrNull() ?: 443
                }
            }
        } else if (host.contains("/")) {
            val slashParts = host.split("/", limit = 2)
            host = slashParts[0]
            path = "/" + slashParts[1]
        }

        return ParsedConfig(
            protocol = "direct",
            address = host,
            port = port,
            host = host,
            sni = host,
            path = path,
            security = "tls",
            transport = "ws",
            tag = "Custom-Direct",
            rawLink = text
        )
    }

    fun generateModifiedLink(parsed: ParsedConfig, cleanIp: String, customPort: Int?, remarkSuffix: String = ""): String {
        val targetPort = customPort ?: parsed.port
        val copy = if (targetPort != parsed.port) parsed.copy(port = targetPort) else parsed
        return generateModifiedLink(copy, cleanIp, remarkSuffix)
    }

    fun generateModifiedLink(parsed: ParsedConfig, cleanIp: String, remarkSuffix: String = ""): String {
        val origDomain = parsed.getSniOrHost()
        val rawIp = cleanIp.trim().removeSurrounding("[", "]")
        val isIpv6 = rawIp.contains(":")
        val formattedIp = if (isIpv6) "[$rawIp]" else rawIp

        val tag = if (remarkSuffix.isNotEmpty()) {
            "${parsed.tag} | CF:$rawIp [$remarkSuffix]"
        } else {
            "${parsed.tag} | CF:$rawIp"
        }

        return when (parsed.protocol) {
            "vless" -> {
                val params = parsed.extraParams.toMutableMap()
                params["type"] = parsed.transport
                params["security"] = parsed.security
                params["path"] = encodePath(parsed.path)
                params["host"] = parsed.host.ifEmpty { origDomain }
                params["sni"] = parsed.sni.ifEmpty { origDomain }
                if (parsed.alpn.isNotEmpty()) params["alpn"] = parsed.alpn
                if (parsed.fingerprint.isNotEmpty()) params["fp"] = parsed.fingerprint
                if (parsed.flow.isNotEmpty()) params["flow"] = parsed.flow
                if (parsed.encryption.isNotEmpty() && parsed.encryption != "none") {
                    params["encryption"] = parsed.encryption
                }
                if (parsed.mode.isNotEmpty()) params["mode"] = parsed.mode

                val queryStr = params.entries.joinToString("&") { (k, v) ->
                    "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}"
                }
                val encodedTag = URLEncoder.encode(tag, "UTF-8")
                "vless://${parsed.uuid}@$formattedIp:${parsed.port}?$queryStr#$encodedTag"
            }
            "vmess" -> {
                val json = JSONObject()
                for ((k, v) in parsed.extraParams) {
                    json.put(k, v)
                }
                json.put("v", "2")
                json.put("ps", tag)
                json.put("add", rawIp)
                json.put("port", parsed.port.toString())
                json.put("id", parsed.uuid)
                json.put("net", parsed.transport)
                json.put("type", "none")
                json.put("host", parsed.host.ifEmpty { origDomain })
                json.put("path", parsed.path)
                json.put("tls", if (parsed.security == "tls") "tls" else "")
                json.put("sni", parsed.sni.ifEmpty { origDomain })

                val jsonBytes = json.toString().toByteArray(Charsets.UTF_8)
                val b64 = Base64.getEncoder().encodeToString(jsonBytes)
                "vmess://$b64"
            }
            "trojan" -> {
                val params = parsed.extraParams.toMutableMap()
                params["type"] = parsed.transport
                params["security"] = parsed.security
                params["path"] = encodePath(parsed.path)
                params["host"] = parsed.host.ifEmpty { origDomain }
                params["sni"] = parsed.sni.ifEmpty { origDomain }
                if (parsed.alpn.isNotEmpty()) params["alpn"] = parsed.alpn
                if (parsed.fingerprint.isNotEmpty()) params["fp"] = parsed.fingerprint

                val queryStr = params.entries.joinToString("&") { (k, v) ->
                    "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}"
                }
                val encodedTag = URLEncoder.encode(tag, "UTF-8")
                "trojan://${parsed.uuid}@$formattedIp:${parsed.port}?$queryStr#$encodedTag"
            }
            "ss" -> {
                val encodedTag = URLEncoder.encode(tag, "UTF-8")
                "ss://${parsed.uuid}@$formattedIp:${parsed.port}#$encodedTag"
            }
            else -> "$formattedIp:${parsed.port} (Host: $origDomain)"
        }
    }

    fun isIp(address: String?): Boolean {
        if (address.isNullOrEmpty()) return false
        val ipv4Pattern = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
        if (ipv4Pattern.matcher(address).matches()) return true
        if (address.contains(":")) return true
        return false
    }

    private fun decodeSsUserInfo(userInfo: String): String {
        if (userInfo.contains(":")) return userInfo
        var b64 = userInfo
        val pad = b64.length % 4
        if (pad != 0) b64 += "=".repeat(4 - pad)
        return try {
            val bytes = try {
                Base64.getUrlDecoder().decode(b64)
            } catch (_: Exception) {
                Base64.getDecoder().decode(b64)
            }
            val str = String(bytes, Charsets.UTF_8)
            if (str.contains(":")) str else userInfo
        } catch (_: Exception) {
            userInfo
        }
    }

    private fun parseQuery(query: String): MutableMap<String, String> {
        val map = mutableMapOf<String, String>()
        if (query.isEmpty()) return map
        val pairs = query.split("&")
        for (pair in pairs) {
            if (pair.isEmpty()) continue
            val idx = pair.indexOf("=")
            if (idx > 0) {
                val key = try { URLDecoder.decode(pair.substring(0, idx), "UTF-8") } catch (_: Exception) { pair.substring(0, idx) }
                val value = try { URLDecoder.decode(pair.substring(idx + 1), "UTF-8") } catch (_: Exception) { pair.substring(idx + 1) }
                map[key] = value
            } else {
                val key = try { URLDecoder.decode(pair, "UTF-8") } catch (_: Exception) { pair }
                map[key] = ""
            }
        }
        return map
    }

    private fun encodePath(path: String): String {
        return path
    }
}

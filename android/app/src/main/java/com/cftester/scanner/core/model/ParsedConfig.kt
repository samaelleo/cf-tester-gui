package com.cftester.scanner.core.model

import java.io.Serializable

data class ParsedConfig(
    val protocol: String = "vless",     // vless, vmess, trojan, ss, direct
    val address: String = "",           // server domain or clean IP
    val port: Int = 443,
    val uuid: String = "",              // uuid or password
    val security: String = "tls",       // tls, reality, none
    val transport: String = "ws",       // ws, grpc, httpupgrade, xhttp, splithttp, tcp
    val path: String = "/",
    val host: String = "",              // Host header
    val sni: String = "",               // SNI
    val alpn: String = "",
    val fingerprint: String = "chrome",
    val flow: String = "",
    val pbk: String = "",               // Reality public key
    val sid: String = "",               // Reality short ID
    val spx: String = "",               // Reality spiderX
    val encryption: String = "none",    // none, mlkem768...
    val mode: String = "",              // packet-up, etc.
    val tag: String = "Cloudflare-Config",
    val rawLink: String = "",
    val rawUri: String = rawLink,
    val cleanIp: String = address,
    val extra: Map<String, Any> = emptyMap(),
    val extraParams: Map<String, String> = emptyMap()
) : Serializable {

    fun getSniOrHost(): String {
        if (sni.isNotEmpty()) return sni
        if (host.isNotEmpty()) return host
        return address
    }

    fun getHostHeader(): String {
        if (host.isNotEmpty()) return host
        if (sni.isNotEmpty()) return sni
        return address
    }
}

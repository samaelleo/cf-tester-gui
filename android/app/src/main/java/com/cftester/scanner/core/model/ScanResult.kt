package com.cftester.scanner.core.model

import java.io.Serializable

data class ScanResult(
    val ip: String = "",
    val prefix: String = "",
    val port: Int = 443,
    val protocol: String = "VLESS",
    val status: String = "FAILED",             // "SUCCESS", "FAILED", "TIMEOUT", "REFUSED"
    var googleStatus: String = "FAIL",         // "204 Google OK", "101 WS OK", "200 OK", etc.
    var googleLatencyMs: Float = 0f,
    var realDelayMs: Float = 0f,
    val tcpLatencyMs: Float = 0f,
    val tlsLatencyMs: Float = 0f,
    val wsLatencyMs: Float = 0f,
    val vlessLatencyMs: Float = 0f,
    val totalLatencyMs: Float = 0f,
    val httpCode: Int = 0,
    val modifiedLink: String = "",
    val errorMsg: String = "",
    val timestamp: Long = System.currentTimeMillis(),
    val candidate: ScanCandidate = ScanCandidate(ip, port, prefix, ip.contains(":"))
) : Serializable

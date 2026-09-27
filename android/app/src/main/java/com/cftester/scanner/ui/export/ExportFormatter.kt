package com.cftester.scanner.ui.export

import com.cftester.scanner.core.model.ScanResult
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

/**
 * Pure Kotlin formatter for scanner results.
 * Matches desktop app_server.py export formats exactly.
 */
object ExportFormatter {

    /**
     * Formats clean IPs as newline-separated list (matching clean_ips.txt).
     */
    fun formatIpsTxt(results: List<ScanResult>): String {
        return results
            .map { it.ip.trim() }
            .filter { it.isNotEmpty() }
            .joinToString("\n")
    }

    /**
     * Formats modified config links as newline-separated list (matching clean_configs.txt).
     */
    fun formatLinksTxt(results: List<ScanResult>): String {
        return results
            .map { it.modifiedLink.trim() }
            .filter { it.isNotEmpty() }
            .joinToString("\n")
    }

    /**
     * Formats a human-readable summary report (matching cloudflare_report.txt).
     */
    fun formatReportTxt(results: List<ScanResult>): String {
        val sb = StringBuilder()
        sb.append("# Cloudflare Clean IPs - Sorted by Google Connectivity Check Latency\n\n")
        if (results.isEmpty()) {
            sb.append("No working clean IPs found.\n")
            return sb.toString()
        }

        results.forEachIndexed { index, r ->
            val rank = index + 1
            val googleLatency = String.format(Locale.US, "%.1f", r.googleLatencyMs)
            val tcpLatency = String.format(Locale.US, "%.1f", r.tcpLatencyMs)
            sb.append("$rank. ${r.ip} | Google: ${googleLatency}ms | TCP: ${tcpLatency}ms | ${r.googleStatus}\n")
            if (r.modifiedLink.isNotEmpty()) {
                sb.append("   Config: ${r.modifiedLink}\n\n")
            }
        }
        return sb.toString().trimEnd() + "\n"
    }

    /**
     * Formats results as RFC 4180 compliant CSV (matching cloudflare_clean_ips.csv).
     */
    fun formatCsv(results: List<ScanResult>): String {
        val sb = StringBuilder()
        sb.append("Rank,IP,Prefix,Google_Latency_ms,TCP_Latency_ms,TLS_Latency_ms,Status,Config_Link\n")
        if (results.isEmpty()) {
            return sb.toString()
        }

        results.forEachIndexed { index, r ->
            val rank = (index + 1).toString()
            val ip = escapeCsv(r.ip)
            val prefix = escapeCsv(r.prefix)
            val googleLat = String.format(Locale.US, "%.1f", r.googleLatencyMs)
            val tcpLat = String.format(Locale.US, "%.1f", r.tcpLatencyMs)
            val tlsLat = String.format(Locale.US, "%.1f", r.tlsLatencyMs)
            val status = escapeCsv(r.googleStatus)
            val configLink = escapeCsv(r.modifiedLink)

            sb.append("$rank,$ip,$prefix,$googleLat,$tcpLat,$tlsLat,$status,$configLink\n")
        }
        return sb.toString()
    }

    /**
     * Formats results as JSON array matching desktop ScanResult.to_dict() schema.
     */
    fun formatJson(results: List<ScanResult>): String {
        val jsonArray = JSONArray()
        for (r in results) {
            val obj = JSONObject()
            obj.put("ip", r.ip)
            obj.put("prefix", r.prefix)
            obj.put("port", r.port)
            obj.put("protocol", r.protocol.lowercase(Locale.US))
            obj.put("status", r.status)
            obj.put("google_status", r.googleStatus)
            obj.put("google_latency_ms", r.googleLatencyMs.toDouble())
            obj.put("real_delay_ms", r.realDelayMs.toDouble())
            obj.put("tcp_latency_ms", r.tcpLatencyMs.toDouble())
            obj.put("tls_latency_ms", r.tlsLatencyMs.toDouble())
            obj.put("ws_latency_ms", r.wsLatencyMs.toDouble())
            obj.put("vless_latency_ms", r.vlessLatencyMs.toDouble())
            obj.put("total_latency_ms", r.totalLatencyMs.toDouble())
            obj.put("http_code", r.httpCode)
            obj.put("modified_link", r.modifiedLink)
            obj.put("error_msg", r.errorMsg)
            obj.put("timestamp", r.timestamp)
            jsonArray.put(obj)
        }
        return jsonArray.toString(2)
    }

    /**
     * Formats single config for proxy app Share Intent (v2rayNG / NekoBox).
     */
    fun formatShareIntentSingle(link: String, remark: String = "CF Clean Config"): String {
        val cleanLink = link.trim()
        if (cleanLink.isEmpty()) return ""
        return "# $remark\n$cleanLink"
    }

    /**
     * Formats multiple configs for proxy app Share Intent.
     */
    fun formatShareIntentMultiple(results: List<ScanResult>, delimiter: String = "\n"): String {
        return results
            .map { it.modifiedLink.trim() }
            .filter { it.isNotEmpty() }
            .joinToString(delimiter)
    }

    /**
     * Escapes a CSV field according to RFC 4180.
     */
    fun escapeCsv(value: String): String {
        if (value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r")) {
            return "\"${value.replace("\"", "\"\"")}\""
        }
        return value
    }
}

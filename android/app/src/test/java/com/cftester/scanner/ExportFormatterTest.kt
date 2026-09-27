package com.cftester.scanner

import com.cftester.scanner.core.model.ScanResult
import com.cftester.scanner.ui.export.ExportFormatter
import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Test

class ExportFormatterTest {

    private val sampleResults = listOf(
        ScanResult(
            ip = "104.16.24.1",
            prefix = "104.16.0.0/12",
            port = 443,
            protocol = "vless",
            status = "SUCCESS",
            googleStatus = "204 OK",
            googleLatencyMs = 65.0f,
            tcpLatencyMs = 42.0f,
            tlsLatencyMs = 50.0f,
            wsLatencyMs = 60.0f,
            vlessLatencyMs = 65.0f,
            totalLatencyMs = 65.0f,
            httpCode = 204,
            modifiedLink = "vless://uuid@104.16.24.1:443?type=ws&security=tls#Tag1"
        ),
        ScanResult(
            ip = "104.16.24.2",
            prefix = "104.16.0.0/12",
            port = 443,
            protocol = "vless",
            status = "SUCCESS",
            googleStatus = "204 OK",
            googleLatencyMs = 120.0f,
            tcpLatencyMs = 50.0f,
            tlsLatencyMs = 60.0f,
            wsLatencyMs = 100.0f,
            vlessLatencyMs = 120.0f,
            totalLatencyMs = 120.0f,
            httpCode = 204,
            modifiedLink = "vless://uuid@104.16.24.2:443?type=ws&security=tls#Tag2"
        )
    )

    @Test
    fun testFormatIpsTxt() {
        val output = ExportFormatter.formatIpsTxt(sampleResults)
        val expected = "104.16.24.1\n104.16.24.2"
        assertEquals(expected, output)
    }

    @Test
    fun testFormatLinksTxt() {
        val output = ExportFormatter.formatLinksTxt(sampleResults)
        assertTrue(output.contains("vless://uuid@104.16.24.1:443"))
        assertTrue(output.contains("vless://uuid@104.16.24.2:443"))
        assertEquals(2, output.lines().size)
    }

    @Test
    fun testFormatReportTxt() {
        val output = ExportFormatter.formatReportTxt(sampleResults)
        assertTrue(output.startsWith("# Cloudflare Clean IPs - Sorted by Google Connectivity Check Latency"))
        assertTrue(output.contains("1. 104.16.24.1 | Google: 65.0ms | TCP: 42.0ms | 204 OK"))
        assertTrue(output.contains("2. 104.16.24.2 | Google: 120.0ms | TCP: 50.0ms | 204 OK"))
        assertTrue(output.contains("Config: vless://uuid@104.16.24.1:443"))
    }

    @Test
    fun testFormatCsv() {
        val output = ExportFormatter.formatCsv(sampleResults)
        val lines = output.lines().filter { it.isNotEmpty() }
        assertEquals(3, lines.size)
        assertEquals("Rank,IP,Prefix,Google_Latency_ms,TCP_Latency_ms,TLS_Latency_ms,Status,Config_Link", lines[0])
        assertTrue(lines[1].startsWith("1,104.16.24.1,104.16.0.0/12,65.0,42.0,50.0,204 OK,"))
        assertTrue(lines[2].startsWith("2,104.16.24.2,104.16.0.0/12,120.0,50.0,60.0,204 OK,"))
    }

    @Test
    fun testFormatJson() {
        val output = ExportFormatter.formatJson(sampleResults)
        val jsonArray = JSONArray(output)
        assertEquals(2, jsonArray.length())
        val first = jsonArray.getJSONObject(0)
        assertEquals("104.16.24.1", first.getString("ip"))
        assertEquals(65.0, first.getDouble("google_latency_ms"), 0.001)
        assertEquals("204 OK", first.getString("google_status"))
        assertEquals("vless", first.getString("protocol"))
    }

    @Test
    fun testShareIntentSinglePayload() {
        val link = "vless://uuid@104.16.24.1:443?type=ws&security=tls"
        val payload = ExportFormatter.formatShareIntentSingle(link)
        assertEquals("# CF Clean Config\n$link", payload)
    }

    @Test
    fun testShareIntentMultiplePayload() {
        val payload = ExportFormatter.formatShareIntentMultiple(sampleResults)
        val lines = payload.lines()
        assertEquals(2, lines.size)
        assertTrue(lines[0].startsWith("vless://"))
        assertTrue(lines[1].startsWith("vless://"))
    }

    @Test
    fun testEmptyResults() {
        assertEquals("", ExportFormatter.formatIpsTxt(emptyList()))
        assertEquals("", ExportFormatter.formatLinksTxt(emptyList()))
        assertTrue(ExportFormatter.formatReportTxt(emptyList()).contains("No working clean IPs found."))
        val csv = ExportFormatter.formatCsv(emptyList())
        assertTrue(csv.startsWith("Rank,IP,Prefix"))
        assertEquals(2, csv.lines().size) // Header line + trailing newline
        val json = ExportFormatter.formatJson(emptyList())
        assertEquals("[]", json.trim())
        assertEquals("", ExportFormatter.formatShareIntentMultiple(emptyList()))
    }

    @Test
    fun testLargePayloadFormat() {
        val largeList = (0 until 1000).map { i ->
            ScanResult(
                ip = "104.16.${i / 256}.${i % 256}",
                prefix = "104.16.0.0/12",
                googleLatencyMs = 50.0f + (i % 100)
            )
        }
        val ipsTxt = ExportFormatter.formatIpsTxt(largeList)
        assertTrue(ipsTxt.length > 10000)
        assertEquals(1000, ipsTxt.lines().size)
    }

    @Test
    fun testCsvEscaping() {
        val escaped = ExportFormatter.escapeCsv("hello, world")
        assertEquals("\"hello, world\"", escaped)
        val quotes = ExportFormatter.escapeCsv("say \"hi\"")
        assertEquals("\"say \"\"hi\"\"\"", quotes)
        val plain = ExportFormatter.escapeCsv("104.16.24.1")
        assertEquals("104.16.24.1", plain)
    }
}

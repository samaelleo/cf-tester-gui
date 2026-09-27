package com.cftester.scanner.core.bgp

import com.cftester.scanner.core.model.SamplingMode
import com.cftester.scanner.core.model.ScanCandidate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.io.Serializable
import java.util.concurrent.TimeUnit

// Supported BGP Sampling Modes: RANDOM, GATEWAY_HOSTS, STEP, ALL, CUSTOM
val SUPPORTED_SAMPLING_MODES = listOf(
    SamplingMode.RANDOM,
    SamplingMode.GATEWAY_HOSTS,
    SamplingMode.STEP,
    SamplingMode.ALL,
    SamplingMode.CUSTOM
)


data class CandidateIp(
    val ip: String,
    val prefix: String = "",
    val isIpv6: Boolean = ip.contains(":")
) : Serializable {
    fun toScanCandidate(port: Int = 443): ScanCandidate =
        ScanCandidate(ip = ip, port = port, prefix = prefix, isIpv6 = isIpv6)
}

data class BgpPrefixResult(
    val status: String,
    val asn: String,
    val ipv4: List<String>,
    val ipv6: List<String>,
    val totalV4: Int,
    val totalV6: Int,
    val source: String
) : Serializable

class BgpFetcher(
    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()
) {
    companion object {
        val FALLBACK_CLOUDFLARE_V4: List<String> = listOf(
            "173.245.48.0/20",
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "141.101.64.0/18",
            "108.162.192.0/18",
            "190.93.240.0/20",
            "188.114.96.0/20",
            "197.234.240.0/22",
            "198.41.128.0/17",
            "162.158.0.0/15",
            "104.16.0.0/13",
            "104.24.0.0/14",
            "172.64.0.0/13",
            "131.0.72.0/22"
        )

        val FALLBACK_CLOUDFLARE_V6: List<String> = listOf(
            "2400:cb00::/32",
            "2606:4700::/32",
            "2803:f800::/32",
            "2405:b500::/32",
            "2405:8100::/32",
            "2a06:98c0::/29",
            "2c0f:f248::/32"
        )
    }

    private val cache = mutableMapOf<String, BgpPrefixResult>()

    fun cleanAsn(asnInput: String): String {
        val trimmed = asnInput.trim().uppercase()
        val withoutAs = if (trimmed.startsWith("AS")) trimmed.substring(2) else trimmed
        val digits = withoutAs.filter { it.isDigit() }
        return if (digits.isNotEmpty()) digits else "13335"
    }

    suspend fun fetchPrefixes(asn: String = "13335"): BgpPrefixResult = withContext(Dispatchers.IO) {
        val clean = cleanAsn(asn)
        cache[clean]?.let { return@withContext it }

        val url = "https://bgp.he.net/super-lg/report/api/v1/prefixes/originated/$clean"
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", "Mozilla/5.0 (Android; Mobile; cf-tester)")
            .header("Accept", "application/json, text/plain, */*")
            .build()

        try {
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val body = response.body?.string() ?: ""
                    val json = JSONObject(body)
                    val prefixesArr = json.optJSONArray("prefixes") ?: JSONArray()

                    val v4 = mutableListOf<String>()
                    val v6 = mutableListOf<String>()

                    for (i in 0 until prefixesArr.length()) {
                        val item = prefixesArr.get(i)
                        val prefix = if (item is JSONObject) item.optString("Prefix") else item.toString()
                        if (prefix.isBlank()) continue
                        val cleanPrefix = prefix.trim()
                        if (cleanPrefix.contains(":")) {
                            v6.add(cleanPrefix)
                        } else {
                            v4.add(cleanPrefix)
                        }
                    }

                    val res = BgpPrefixResult(
                        status = "success",
                        asn = "AS$clean",
                        ipv4 = v4,
                        ipv6 = v6,
                        totalV4 = v4.size,
                        totalV6 = v6.size,
                        source = "Hurricane Electric BGP API"
                    )
                    cache[clean] = res
                    return@withContext res
                }
            }
        } catch (_: Exception) {
            // Gracefully fall back below
        }

        val fallback = BgpPrefixResult(
            status = "fallback",
            asn = "AS$clean",
            ipv4 = FALLBACK_CLOUDFLARE_V4,
            ipv6 = FALLBACK_CLOUDFLARE_V6,
            totalV4 = FALLBACK_CLOUDFLARE_V4.size,
            totalV6 = FALLBACK_CLOUDFLARE_V6.size,
            source = "Local Fallback List"
        )
        cache[clean] = fallback
        fallback
    }

    fun generateCandidateIps(
        prefixes: List<String>,
        sampleMode: SamplingMode = SamplingMode.RANDOM,
        ipsPerPrefix: Int = 2,
        maxTotalIps: Int = 5000,
        customIpList: List<String>? = null
    ): List<ScanCandidate> {
        if (!customIpList.isNullOrEmpty()) {
            return SubnetCalculator.generateFromCustomList(customIpList, ipsPerPrefix, maxTotalIps)
        }
        return SubnetCalculator.sampleSubnets(prefixes, sampleMode, ipsPerPrefix, maxTotalIps)
    }
}

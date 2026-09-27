package com.cftester.scanner

import com.cftester.scanner.core.bgp.BgpFetcher
import com.cftester.scanner.core.bgp.FallbackRanges
import com.cftester.scanner.core.bgp.SubnetCalculator
import com.cftester.scanner.core.model.SamplingMode
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class BgpFetcherTest {

    private lateinit var fetcher: BgpFetcher

    @Before
    fun setUp() {
        fetcher = BgpFetcher()
    }

    @Test
    fun testCleanAsn() {
        assertEquals("13335", fetcher.cleanAsn("AS13335"))
        assertEquals("13335", fetcher.cleanAsn("as13335"))
        assertEquals("209242", fetcher.cleanAsn("AS209242"))
        assertEquals("13335", fetcher.cleanAsn("  AS 13335 \n"))
        assertEquals("13335", fetcher.cleanAsn(""))
        assertEquals("13335", fetcher.cleanAsn("AS-XYZ"))
    }

    @Test
    fun testFallbackRangesLoaded() {
        assertEquals(15, FallbackRanges.CLOUDFLARE_V4.size)
        assertTrue(FallbackRanges.CLOUDFLARE_V4.contains("173.245.48.0/20"))
        assertTrue(FallbackRanges.CLOUDFLARE_V4.contains("104.16.0.0/13"))
        assertTrue(FallbackRanges.CLOUDFLARE_V4.contains("131.0.72.0/22"))

        assertEquals(7, FallbackRanges.CLOUDFLARE_V6.size)
        assertTrue(FallbackRanges.CLOUDFLARE_V6.contains("2606:4700::/32"))
        assertTrue(FallbackRanges.CLOUDFLARE_V6.contains("2400:cb00::/32"))
    }

    @Test
    fun testCandidateGenerationRandom() {
        val prefixes = listOf("104.16.0.0/13")
        val candidates = fetcher.generateCandidateIps(
            prefixes = prefixes,
            sampleMode = SamplingMode.RANDOM,
            ipsPerPrefix = 5,
            maxTotalIps = 10
        )
        assertFalse(candidates.isEmpty())
        assertTrue(candidates.size <= 5)
        for (c in candidates) {
            assertTrue(c.ip.startsWith("104.") || c.ip.startsWith("104.16"))
            assertFalse(c.isIpv6)
            assertEquals("104.16.0.0/13", c.prefix)
        }
    }

    @Test
    fun testCandidateGenerationGatewayHosts() {
        val prefixes = listOf("173.245.48.0/20")
        val candidates = fetcher.generateCandidateIps(
            prefixes = prefixes,
            sampleMode = SamplingMode.GATEWAY_HOSTS,
            ipsPerPrefix = 4,
            maxTotalIps = 10
        )
        assertEquals(4, candidates.size)
        // Standard edge offsets: .1, .2, .10, .20 from network base 173.245.48.0
        val ips = candidates.map { it.ip }
        assertTrue(ips.contains("173.245.48.1"))
        assertTrue(ips.contains("173.245.48.2"))
    }

    @Test
    fun testCandidateGenerationStep() {
        val prefixes = listOf("103.21.244.0/22")
        val candidates = fetcher.generateCandidateIps(
            prefixes = prefixes,
            sampleMode = SamplingMode.STEP,
            ipsPerPrefix = 3,
            maxTotalIps = 10
        )
        assertEquals(3, candidates.size)
        // Ensure candidates are distinct
        assertEquals(3, candidates.map { it.ip }.toSet().size)
    }

    @Test
    fun testCandidateGenerationIpv6() {
        val prefixes = listOf("2606:4700::/32")
        val candidates = fetcher.generateCandidateIps(
            prefixes = prefixes,
            sampleMode = SamplingMode.GATEWAY_HOSTS,
            ipsPerPrefix = 3,
            maxTotalIps = 10
        )
        assertEquals(3, candidates.size)
        for (c in candidates) {
            assertTrue(c.isIpv6)
            assertTrue(c.ip.contains(":"))
        }
    }

    @Test
    fun testCandidateGenerationCustomList() {
        val custom = listOf("104.16.24.1", "2606:4700::1", "103.22.200.0/24")
        val candidates = fetcher.generateCandidateIps(
            prefixes = emptyList(),
            sampleMode = SamplingMode.CUSTOM,
            ipsPerPrefix = 2,
            maxTotalIps = 10,
            customIpList = custom
        )
        assertTrue(candidates.size >= 3)
        val ips = candidates.map { it.ip }
        assertTrue(ips.contains("104.16.24.1"))
        assertTrue(ips.contains("2606:4700::1"))
    }

    @Test
    fun testCandidateGenerationBoundarySubnets() {
        // Single host /32
        val candidatesV4 = SubnetCalculator.sampleSubnets(listOf("1.1.1.1/32"), SamplingMode.RANDOM, 2, 10)
        assertEquals(1, candidatesV4.size)
        assertEquals("1.1.1.1", candidatesV4[0].ip)

        // Single host /128
        val candidatesV6 = SubnetCalculator.sampleSubnets(listOf("2606:4700::1/128"), SamplingMode.RANDOM, 2, 10)
        assertEquals(1, candidatesV6.size)
        assertTrue(candidatesV6[0].ip.contains(":"))
    }

    @Test
    fun testFetchPrefixesFallback() = runBlocking {
        val result = fetcher.fetchPrefixes("AS13335")
        assertNotNull(result)
        assertTrue(result.ipv4.isNotEmpty())
        assertTrue(result.ipv6.isNotEmpty())
        assertEquals("AS13335", result.asn)
    }
}

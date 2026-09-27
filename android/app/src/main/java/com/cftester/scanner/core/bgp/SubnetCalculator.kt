package com.cftester.scanner.core.bgp

import com.cftester.scanner.core.model.SamplingMode
import com.cftester.scanner.core.model.ScanCandidate
import java.math.BigInteger
import java.net.InetAddress
import java.util.Collections
import kotlin.random.Random

object SubnetCalculator {

    fun sampleSubnets(
        prefixes: List<String>,
        mode: SamplingMode = SamplingMode.RANDOM,
        ipsPerPrefix: Int = 2,
        maxTotalIps: Int = 5000
    ): List<ScanCandidate> {
        val results = mutableListOf<ScanCandidate>()
        val seenIps = mutableSetOf<String>()

        val shuffled = prefixes.toMutableList()
        shuffled.shuffle()

        for (prefix in shuffled) {
            if (results.size >= maxTotalIps) break
            try {
                if (prefix.contains(":")) {
                    sampleIpv6Prefix(prefix, mode, ipsPerPrefix, maxTotalIps, results, seenIps)
                } else {
                    sampleIpv4Prefix(prefix, mode, ipsPerPrefix, maxTotalIps, results, seenIps)
                }
            } catch (_: Exception) {
                // Ignore malformed prefix and continue
            }
        }

        return if (results.size > maxTotalIps) results.subList(0, maxTotalIps) else results
    }

    private fun sampleIpv4Prefix(
        prefix: String,
        mode: SamplingMode,
        ipsPerPrefix: Int,
        maxTotalIps: Int,
        results: MutableList<ScanCandidate>,
        seenIps: MutableSet<String>
    ) {
        val parts = prefix.trim().split("/")
        if (parts.size != 2) return
        val ipStr = parts[0]
        val mask = parts[1].toIntOrNull() ?: return
        if (mask !in 0..32) return

        val baseInt = ipv4ToLong(ipStr)
        val hostBits = 32 - mask
        val numAddresses = 1L shl hostBits
        val netMask = if (mask == 0) 0L else (-1L shl hostBits) and 0xFFFFFFFFL
        val netAddress = baseInt and netMask
        val broadcastAddress = netAddress or ((1L shl hostBits) - 1L)

        if (numAddresses <= 2) {
            for (curr in netAddress..broadcastAddress) {
                val ip = longToIpv4(curr)
                if (seenIps.add(ip)) {
                    results.add(ScanCandidate(ip = ip, port = 443, prefix = prefix, isIpv6 = false))
                }
            }
            return
        }

        val firstInt = netAddress + 1
        val lastInt = broadcastAddress - 1
        val totalUsable = (lastInt - firstInt + 1).toInt()

        when (mode) {
            SamplingMode.RANDOM -> {
                val count = ipsPerPrefix.coerceIn(1, totalUsable)
                val sampled = mutableListOf<Long>()
                val rangeList = (firstInt..lastInt).toList()
                val shuffledRange = rangeList.shuffled()
                for (i in 0 until minOf(count, shuffledRange.size)) {
                    sampled.add(shuffledRange[i])
                }
                for (cand in sampled) {
                    val ip = longToIpv4(cand)
                    if (seenIps.add(ip)) {
                        results.add(ScanCandidate(ip = ip, port = 443, prefix = prefix, isIpv6 = false))
                    }
                }
            }
            SamplingMode.GATEWAY_HOSTS -> {
                val offsets = listOf(1, 2, 10, 20, 50, 100, 150, 200, 254)
                var added = 0
                for (off in offsets) {
                    val cand = netAddress + off
                    if (cand in firstInt..lastInt) {
                        val ip = longToIpv4(cand)
                        if (seenIps.add(ip)) {
                            results.add(ScanCandidate(ip = ip, port = 443, prefix = prefix, isIpv6 = false))
                            added++
                            if (added >= ipsPerPrefix) break
                        }
                    }
                }
            }
            SamplingMode.STEP -> {
                val step = maxOf(1, totalUsable / maxOf(1, ipsPerPrefix))
                for (i in 0 until ipsPerPrefix) {
                    val cand = firstInt + (i * step)
                    if (cand <= lastInt) {
                        val ip = longToIpv4(cand)
                        if (seenIps.add(ip)) {
                            results.add(ScanCandidate(ip = ip, port = 443, prefix = prefix, isIpv6 = false))
                        }
                    }
                }
            }
            SamplingMode.ALL -> {
                for (cand in firstInt..lastInt) {
                    val ip = longToIpv4(cand)
                    if (seenIps.add(ip)) {
                        results.add(ScanCandidate(ip = ip, port = 443, prefix = prefix, isIpv6 = false))
                    }
                    if (results.size >= maxTotalIps) break
                }
            }
            SamplingMode.CUSTOM -> {
                // Handled in generateFromCustomList
            }
        }
    }

    private fun sampleIpv6Prefix(
        prefix: String,
        mode: SamplingMode,
        ipsPerPrefix: Int,
        maxTotalIps: Int,
        results: MutableList<ScanCandidate>,
        seenIps: MutableSet<String>
    ) {
        val parts = prefix.trim().split("/")
        if (parts.size != 2) return
        val ipStr = parts[0]
        val prefixLen = parts[1].toIntOrNull() ?: return
        if (prefixLen !in 0..128) return

        val addr = InetAddress.getByName(ipStr)
        val addrBytes = addr.address
        if (addrBytes.size != 16) return
        val rawInt = BigInteger(1, addrBytes)

        val hostBits = 128 - prefixLen
        val netMask = if (prefixLen == 0) BigInteger.ZERO else BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE).shiftLeft(hostBits).and(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE))
        val netInt = rawInt.and(netMask)
        val numAddresses = BigInteger.ONE.shiftLeft(hostBits)

        if (numAddresses <= BigInteger.valueOf(2)) {
            var curr = netInt
            while (curr <= netInt.add(numAddresses.subtract(BigInteger.ONE))) {
                val ip = bigIntToIpv6(curr)
                if (seenIps.add(ip)) {
                    results.add(ScanCandidate(ip = ip, port = 443, prefix = prefix, isIpv6 = true))
                }
                curr = curr.add(BigInteger.ONE)
            }
            return
        }

        val maxOffsetLong = numAddresses.subtract(BigInteger.ONE).min(BigInteger.valueOf(0x10000L)).toLong()
        val maxOffset = maxOffsetLong.toInt().coerceAtLeast(1)

        when (mode) {
            SamplingMode.GATEWAY_HOSTS -> {
                val offsets = listOf(1, 2, 0x10, 0x20, 0x50, 0x100, 0x200)
                var added = 0
                for (off in offsets) {
                    if (off <= maxOffset) {
                        val candInt = netInt.add(BigInteger.valueOf(off.toLong()))
                        val ip = bigIntToIpv6(candInt)
                        if (seenIps.add(ip)) {
                            results.add(ScanCandidate(ip = ip, port = 443, prefix = prefix, isIpv6 = true))
                            added++
                            if (added >= ipsPerPrefix) break
                        }
                    }
                }
            }
            SamplingMode.RANDOM -> {
                val count = ipsPerPrefix.coerceIn(1, maxOffset)
                val sampled = mutableListOf<Int>()
                val rangeList = (1..maxOffset).toList().shuffled()
                for (i in 0 until minOf(count, rangeList.size)) {
                    sampled.add(rangeList[i])
                }
                for (off in sampled) {
                    val candInt = netInt.add(BigInteger.valueOf(off.toLong()))
                    val ip = bigIntToIpv6(candInt)
                    if (seenIps.add(ip)) {
                        results.add(ScanCandidate(ip = ip, port = 443, prefix = prefix, isIpv6 = true))
                    }
                }
            }
            SamplingMode.STEP -> {
                val step = maxOf(1, maxOffset / maxOf(1, ipsPerPrefix))
                for (i in 0 until ipsPerPrefix) {
                    val off = 1 + (i * step)
                    if (off <= maxOffset) {
                        val candInt = netInt.add(BigInteger.valueOf(off.toLong()))
                        val ip = bigIntToIpv6(candInt)
                        if (seenIps.add(ip)) {
                            results.add(ScanCandidate(ip = ip, port = 443, prefix = prefix, isIpv6 = true))
                        }
                    }
                }
            }
            SamplingMode.ALL -> {
                val count = ipsPerPrefix.coerceIn(1, maxOffset)
                for (i in 1..count) {
                    val candInt = netInt.add(BigInteger.valueOf(i.toLong()))
                    val ip = bigIntToIpv6(candInt)
                    if (seenIps.add(ip)) {
                        results.add(ScanCandidate(ip = ip, port = 443, prefix = prefix, isIpv6 = true))
                    }
                    if (results.size >= maxTotalIps) break
                }
            }
            SamplingMode.CUSTOM -> {}
        }
    }

    fun generateFromCustomList(
        customList: List<String>,
        ipsPerPrefix: Int = 2,
        maxTotalIps: Int = 5000
    ): List<ScanCandidate> {
        val results = mutableListOf<ScanCandidate>()
        val seenIps = mutableSetOf<String>()

        for (raw in customList) {
            val item = raw.trim()
            if (item.isEmpty()) continue
            if (results.size >= maxTotalIps) break

            try {
                if (item.contains("/")) {
                    val sampled = sampleSubnets(listOf(item), SamplingMode.RANDOM, ipsPerPrefix, maxTotalIps)
                    for (cand in sampled) {
                        if (seenIps.add(cand.ip)) {
                            results.add(cand)
                            if (results.size >= maxTotalIps) break
                        }
                    }
                } else {
                    InetAddress.getByName(item) // Validate format
                    val ip = item
                    val isV6 = ip.contains(":")
                    if (seenIps.add(ip)) {
                        results.add(ScanCandidate(ip = ip, port = 443, prefix = "Manual", isIpv6 = isV6))
                    }
                }
            } catch (_: Exception) {
                // Skip invalid IP string
            }
        }

        return if (results.size > maxTotalIps) results.subList(0, maxTotalIps) else results
    }

    private fun ipv4ToLong(ipStr: String): Long {
        val parts = ipStr.split(".")
        var res = 0L
        for (p in parts) {
            res = (res shl 8) or (p.toLong() and 0xFF)
        }
        return res
    }

    private fun longToIpv4(value: Long): String {
        return "${(value shr 24) and 0xFF}.${(value shr 16) and 0xFF}.${(value shr 8) and 0xFF}.${value and 0xFF}"
    }

    private fun bigIntToIpv6(bigInt: BigInteger): String {
        val raw = bigInt.toByteArray()
        val bytes = ByteArray(16)
        if (raw.size >= 16) {
            System.arraycopy(raw, raw.size - 16, bytes, 0, 16)
        } else {
            System.arraycopy(raw, 0, bytes, 16 - raw.size, raw.size)
        }
        return InetAddress.getByAddress(bytes).hostAddress ?: bigInt.toString(16)
    }
}

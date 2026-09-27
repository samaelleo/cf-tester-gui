package com.cftester.scanner.core.model

import java.io.Serializable

data class ScanConfig(
    val asn: String = "13335",
    val ipVersion: IpVersion = IpVersion.IPV4,
    val samplingMode: SamplingMode = SamplingMode.RANDOM,
    val maxIps: Int = 2000,
    val ipsPerPrefix: Int = 2,
    val concurrency: Int = 50,
    val timeoutMs: Long = 2500L,
    val candidatePort: Int = 443,
    val candidateSni: String = "",
    val candidateHost: String = "",
    val candidatePath: String = "/",
    val candidateTransport: String = "ws",
    val candidateTls: String = "tls",
    val vlessPayload: ByteArray? = null,
    val customIpList: List<String> = emptyList(),
    val targetUrl: String = "http://connectivitycheck.gstatic.com/generate_204"
) : Serializable {

    val timeoutSec: Float
        get() = timeoutMs / 1000f

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ScanConfig

        if (asn != other.asn) return false
        if (ipVersion != other.ipVersion) return false
        if (samplingMode != other.samplingMode) return false
        if (maxIps != other.maxIps) return false
        if (ipsPerPrefix != other.ipsPerPrefix) return false
        if (concurrency != other.concurrency) return false
        if (timeoutMs != other.timeoutMs) return false
        if (candidatePort != other.candidatePort) return false
        if (candidateSni != other.candidateSni) return false
        if (candidateHost != other.candidateHost) return false
        if (candidatePath != other.candidatePath) return false
        if (candidateTransport != other.candidateTransport) return false
        if (candidateTls != other.candidateTls) return false
        if (customIpList != other.customIpList) return false
        if (targetUrl != other.targetUrl) return false
        if (vlessPayload != null) {
            if (other.vlessPayload == null) return false
            if (!vlessPayload.contentEquals(other.vlessPayload)) return false
        } else if (other.vlessPayload != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = asn.hashCode()
        result = 31 * result + ipVersion.hashCode()
        result = 31 * result + samplingMode.hashCode()
        result = 31 * result + maxIps
        result = 31 * result + ipsPerPrefix
        result = 31 * result + concurrency
        result = 31 * result + timeoutMs.hashCode()
        result = 31 * result + candidatePort
        result = 31 * result + candidateSni.hashCode()
        result = 31 * result + candidateHost.hashCode()
        result = 31 * result + candidatePath.hashCode()
        result = 31 * result + candidateTransport.hashCode()
        result = 31 * result + candidateTls.hashCode()
        result = 31 * result + (vlessPayload?.contentHashCode() ?: 0)
        result = 31 * result + customIpList.hashCode()
        result = 31 * result + targetUrl.hashCode()
        return result
    }
}

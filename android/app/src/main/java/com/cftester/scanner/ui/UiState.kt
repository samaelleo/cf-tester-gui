package com.cftester.scanner.ui

import com.cftester.scanner.core.model.*

data class UiState(
    val isPersian: Boolean = false,
    val configInput: String = "",
    val parsedConfig: ParsedConfig = ParsedConfig(),
    val selectedAsn: String = "13335",
    val customAsn: String = "13335",
    val bgpPrefixCount: Int = 5489,
    val isFetchingBgp: Boolean = false,
    val ipVersion: IpVersion = IpVersion.IPV4,
    val samplingMode: SamplingMode = SamplingMode.RANDOM,
    val customIps: String = "",
    val targetUrl: String = "http://connectivitycheck.gstatic.com/generate_204",
    val ipsPerPrefix: Int = 2,
    val maxIps: Int = 1000,
    val concurrency: Int = 60,
    val timeoutMs: Long = 2500L,
    val isScanning: Boolean = false,
    val isPaused: Boolean = false,
    val isTestingRealDelay: Boolean = false,
    val scanProgress: ScanProgress = ScanProgress(),
    val bestPingMs: Float = 0f,
    val workingResults: List<ScanResult> = emptyList(),
    val searchQuery: String = "",
    val toastMessage: String? = null
)

package com.cftester.scanner.ui

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cftester.scanner.core.bgp.BgpFetcher
import com.cftester.scanner.core.engine.TesterEngine
import com.cftester.scanner.core.model.*
import com.cftester.scanner.core.parser.ConfigParser
import com.cftester.scanner.core.xray.XrayRealDelayTester
import com.cftester.scanner.service.ScanForegroundService
import com.cftester.scanner.ui.export.ExportFormatter
import com.cftester.scanner.ui.export.ShareHelper
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.File

class MainViewModel(
    private val bgpFetcher: BgpFetcher = BgpFetcher(),
    val testerEngine: TesterEngine = TesterEngine()
) : ViewModel() {

    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    private var scanJob: Job? = null
    private var realDelayJob: Job? = null

    init {
        // Collect from ScanForegroundService state
        viewModelScope.launch {
            ScanForegroundService.serviceState.collect { sState ->
                when (sState) {
                    ScanForegroundService.ScanServiceState.RUNNING -> _uiState.update { it.copy(isScanning = true, isPaused = false) }
                    ScanForegroundService.ScanServiceState.PAUSED -> _uiState.update { it.copy(isScanning = true, isPaused = true) }
                    ScanForegroundService.ScanServiceState.COMPLETED,
                    ScanForegroundService.ScanServiceState.STOPPED,
                    ScanForegroundService.ScanServiceState.IDLE,
                    ScanForegroundService.ScanServiceState.ERROR -> _uiState.update { it.copy(isScanning = false, isPaused = false) }
                }
            }
        }

        viewModelScope.launch {
            ScanForegroundService.progressFlow.collect { progress ->
                if (progress.total > 0) {
                    _uiState.update { current ->
                        val newBest = if (progress.working > 0 && current.workingResults.isNotEmpty()) {
                            current.workingResults.minOfOrNull { it.googleLatencyMs } ?: current.bestPingMs
                        } else current.bestPingMs
                        current.copy(scanProgress = progress, bestPingMs = newBest)
                    }
                }
            }
        }

        viewModelScope.launch {
            ScanForegroundService.workingResults.collect { results ->
                if (results.isNotEmpty()) {
                    _uiState.update { current ->
                        val best = results.firstOrNull()?.googleLatencyMs ?: 0f
                        current.copy(workingResults = results, bestPingMs = best)
                    }
                }
            }
        }

        // Also collect from local testerEngine
        viewModelScope.launch {
            testerEngine.progressFlow.collect { progress ->
                _uiState.update { current ->
                    val newBest = if (progress.working > 0 && current.workingResults.isNotEmpty()) {
                        current.workingResults.minOfOrNull { it.googleLatencyMs } ?: current.bestPingMs
                    } else current.bestPingMs
                    current.copy(scanProgress = progress, bestPingMs = newBest)
                }
            }
        }

        viewModelScope.launch {
            testerEngine.workingResultFlow.collect { result ->
                _uiState.update { current ->
                    val updated = (current.workingResults + result)
                        .distinctBy { it.ip }
                        .sortedBy { if (it.googleLatencyMs > 0) it.googleLatencyMs else 99999f }
                    val best = updated.firstOrNull()?.googleLatencyMs ?: 0f
                    current.copy(workingResults = updated, bestPingMs = best)
                }
            }
        }

        viewModelScope.launch {
            testerEngine.isRunning.collect { running ->
                if (running) _uiState.update { it.copy(isScanning = true) }
            }
        }

        viewModelScope.launch {
            testerEngine.isPaused.collect { paused ->
                if (_uiState.value.isScanning) _uiState.update { it.copy(isPaused = paused) }
            }
        }
    }

    fun toggleLanguage() {
        _uiState.update { it.copy(isPersian = !it.isPersian) }
    }

    fun onConfigInputChange(input: String) {
        val parsed = ConfigParser.parse(input)
        _uiState.update { it.copy(configInput = input, parsedConfig = parsed) }
    }

    fun onAsnSelected(asn: String) {
        _uiState.update { it.copy(selectedAsn = asn, customAsn = asn) }
        fetchBgpPrefixes()
    }

    fun onCustomAsnChanged(asn: String) {
        _uiState.update { it.copy(customAsn = asn, selectedAsn = asn.trim()) }
    }

    fun onIpVersionChanged(version: IpVersion) {
        _uiState.update { it.copy(ipVersion = version) }
    }

    fun onSamplingModeChanged(mode: SamplingMode) {
        _uiState.update { it.copy(samplingMode = mode) }
    }

    fun onCustomIpsChanged(ips: String) {
        _uiState.update { it.copy(customIps = ips) }
    }

    fun onIpsPerPrefixChanged(ips: Int) {
        _uiState.update { it.copy(ipsPerPrefix = ips) }
    }

    fun onMaxIpsChanged(max: Int) {
        _uiState.update { it.copy(maxIps = max) }
    }

    fun onConcurrencyChanged(concurrency: Int) {
        _uiState.update { it.copy(concurrency = concurrency) }
    }

    fun onTimeoutChanged(timeoutMs: Long) {
        _uiState.update { it.copy(timeoutMs = timeoutMs) }
    }

    fun onSearchQueryChanged(query: String) {
        _uiState.update { it.copy(searchQuery = query) }
    }

    fun clearToastMessage() {
        _uiState.update { it.copy(toastMessage = null) }
    }

    fun fetchBgpPrefixes() {
        viewModelScope.launch {
            _uiState.update { it.copy(isFetchingBgp = true) }
            try {
                val asn = _uiState.value.selectedAsn
                val res = bgpFetcher.fetchPrefixes(asn)
                val total = res.totalV4 + res.totalV6
                _uiState.update { it.copy(bgpPrefixCount = total, isFetchingBgp = false) }
            } catch (e: Exception) {
                _uiState.update { it.copy(isFetchingBgp = false, toastMessage = "BGP fetch failed: ${e.message}") }
            }
        }
    }

    fun startScan(context: Context? = null) {
        val state = _uiState.value
        _uiState.update { it.copy(workingResults = emptyList(), bestPingMs = 0f, isScanning = true) }

        val prefixes = when (state.ipVersion) {
            IpVersion.IPV6 -> listOf("2606:4700::/32")
            IpVersion.BOTH -> listOf("104.16.0.0/12", "172.64.0.0/13", "2606:4700::/32")
            else -> listOf("104.16.0.0/12", "172.64.0.0/13")
        }

        val customList = if (state.samplingMode == SamplingMode.CUSTOM) {
            state.customIps.lines().map { it.trim() }.filter { it.isNotEmpty() }
        } else emptyList()

        val candidateIps = bgpFetcher.generateCandidateIps(
            prefixes = prefixes,
            sampleMode = state.samplingMode,
            ipsPerPrefix = state.ipsPerPrefix,
            maxTotalIps = state.maxIps,
            customIpList = if (customList.isNotEmpty()) customList else null
        )

        val port = if (state.parsedConfig.port > 0) state.parsedConfig.port else 443
        val candidates = candidateIps.map { c ->
            ScanCandidate(ip = c.ip, port = port, prefix = c.prefix, isIpv6 = c.isIpv6)
        }

        val scanConfig = ScanConfig(
            asn = state.selectedAsn,
            ipVersion = state.ipVersion,
            samplingMode = state.samplingMode,
            maxIps = state.maxIps,
            ipsPerPrefix = state.ipsPerPrefix,
            concurrency = state.concurrency,
            timeoutMs = state.timeoutMs,
            candidatePort = port,
            targetUrl = state.targetUrl
        )

        if (context != null) {
            ScanForegroundService.start(context, candidates, scanConfig, state.parsedConfig)
        } else {
            scanJob?.cancel()
            scanJob = viewModelScope.launch(Dispatchers.Default) {
                testerEngine.runScan(
                    candidates = candidates,
                    config = state.parsedConfig,
                    concurrency = state.concurrency,
                    timeoutSec = state.timeoutMs / 1000f,
                    targetUrl = state.targetUrl
                )
            }
        }
    }

    fun pauseScan(context: Context? = null) {
        if (context != null) {
            ScanForegroundService.pause(context)
        }
        testerEngine.pause()
    }

    fun resumeScan(context: Context? = null) {
        if (context != null) {
            ScanForegroundService.resume(context)
        }
        testerEngine.resume()
    }

    fun stopScan(context: Context? = null) {
        if (context != null) {
            ScanForegroundService.stop(context)
        }
        testerEngine.stop()
        scanJob?.cancel()
        _uiState.update { it.copy(isScanning = false, isPaused = false) }
    }

    fun clearResults() {
        _uiState.update { it.copy(workingResults = emptyList(), bestPingMs = 0f) }
    }

    fun startRealDelayTest(nativeLibDir: File, cacheDir: File) {
        realDelayJob?.cancel()
        realDelayJob = viewModelScope.launch(Dispatchers.IO) {
            _uiState.update { it.copy(isTestingRealDelay = true) }
            val results = _uiState.value.workingResults.toList()
            val parsed = _uiState.value.parsedConfig

            for (res in results) {
                if (!_uiState.value.isTestingRealDelay) break
                try {
                    val delay = XrayRealDelayTester.testRealDelay(
                        nativeLibDir = nativeLibDir,
                        cacheDir = cacheDir,
                        parsed = parsed,
                        cleanIp = res.ip,
                        timeoutMs = _uiState.value.timeoutMs
                    )
                    res.realDelayMs = delay.toFloat()
                } catch (_: Exception) {
                    res.realDelayMs = -1f
                }
                _uiState.update { current ->
                    current.copy(
                        workingResults = current.workingResults.sortedBy {
                            if (it.realDelayMs > 0) it.realDelayMs else (it.googleLatencyMs + 10000f)
                        }
                    )
                }
            }
            _uiState.update { it.copy(isTestingRealDelay = false) }
        }
    }

    // Export & Share Helpers
    fun copyAllIps(context: Context) {
        val ips = ExportFormatter.formatIpsTxt(_uiState.value.workingResults)
        if (ips.isEmpty()) {
            _uiState.update { it.copy(toastMessage = "No clean IPs to copy") }
            return
        }
        val ok = ShareHelper.copyToClipboardSafe(context, "CF Clean IPs", ips)
        val msg = if (ok) "${_uiState.value.workingResults.size} IPs copied!" else "Payload too large for clipboard"
        _uiState.update { it.copy(toastMessage = msg) }
    }

    fun copyIp(context: Context, ip: String) {
        ShareHelper.copyToClipboardSafe(context, "Clean IP", ip)
        _uiState.update { it.copy(toastMessage = "IP copied: $ip") }
    }

    fun copyConfig(context: Context, result: ScanResult) {
        val modLink = ConfigParser.generateModifiedLink(_uiState.value.parsedConfig, result.ip, result.port)
        ShareHelper.copyToClipboardSafe(context, "CF Config", modLink)
        _uiState.update { it.copy(toastMessage = "Config copied!") }
    }

    fun shareConfig(context: Context, result: ScanResult) {
        val modLink = ConfigParser.generateModifiedLink(_uiState.value.parsedConfig, result.ip, result.port)
        val payload = ExportFormatter.formatShareIntentSingle(modLink)
        ShareHelper.shareToProxyApp(context, payload)
    }

    fun shareAllConfigs(context: Context) {
        val links = _uiState.value.workingResults.map { res ->
            ConfigParser.generateModifiedLink(_uiState.value.parsedConfig, res.ip, res.port)
        }.filter { it.isNotEmpty() }

        if (links.isEmpty()) {
            _uiState.update { it.copy(toastMessage = "No clean configs to share") }
            return
        }
        val payload = links.joinToString("\n")
        ShareHelper.shareText(context, payload, "Share All Configs", "CF Clean Configs")
    }
}

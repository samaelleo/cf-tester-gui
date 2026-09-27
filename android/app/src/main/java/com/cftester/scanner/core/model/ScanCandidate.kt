package com.cftester.scanner.core.model

import java.io.Serializable

data class ScanCandidate(
    val ip: String,
    val port: Int = 443,
    val prefix: String = "",
    val isIpv6: Boolean = ip.contains(":")
) : Serializable

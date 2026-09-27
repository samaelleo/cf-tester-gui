package com.cftester.scanner.core.model

import java.io.Serializable

data class ScanProgress(
    val tested: Int = 0,
    val total: Int = 0,
    val working: Int = 0,
    val speed: Float = 0f,
    val latestIp: String = "",
    val latestStatus: String = "",
    val latestLatency: Float = 0f
) : Serializable

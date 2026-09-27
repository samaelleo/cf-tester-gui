package com.cftester.scanner.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cftester.scanner.R
import com.cftester.scanner.ui.UiState
import com.cftester.scanner.ui.theme.*

@Composable
fun MetricsSummaryCard(state: UiState) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .glassCard()
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            MetricBox("📊", stringResource(R.string.lbl_stat_tested), "${state.scanProgress.tested} / ${state.scanProgress.total}", TextPrimary)
            MetricBox("✨", stringResource(R.string.lbl_stat_working), state.workingResults.size.toString(), AccentGreen)
            MetricBox("⚡", stringResource(R.string.lbl_stat_speed), "${state.scanProgress.speed.toInt()} IP/s", AccentPurple)
            MetricBox(
                "🎯",
                stringResource(R.string.lbl_stat_ping),
                if (state.bestPingMs > 0) "${state.bestPingMs.toInt()} ms" else "-- ms",
                AccentAmber
            )
        }

        // Progress Track
        val progressFraction = if (state.scanProgress.total > 0) {
            (state.scanProgress.tested.toFloat() / state.scanProgress.total).coerceIn(0f, 1f)
        } else 0f

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = if (state.isScanning) stringResource(R.string.scanning_text) else stringResource(R.string.ready_text),
                fontSize = 10.sp,
                color = TextSecondary
            )
            LtrText(
                text = "${(progressFraction * 100).toInt()}%",
                style = MaterialTheme.typography.labelSmall,
                color = AccentCyan
            )
        }

        LinearProgressIndicator(
            progress = { progressFraction },
            modifier = Modifier.fillMaxWidth().height(4.dp),
            color = AccentBlue,
            trackColor = DarkBgSurface
        )
    }
}

@Composable
fun RowScope.MetricBox(icon: String, label: String, value: String, valueColor: Color) {
    Column(
        modifier = Modifier.weight(1f),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(icon, fontSize = 14.sp)
        Text(label, fontSize = 8.sp, color = TextSecondary)
        LtrText(value, style = MaterialTheme.typography.titleMedium, color = valueColor)
    }
}

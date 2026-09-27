package com.cftester.scanner.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cftester.scanner.R
import com.cftester.scanner.core.model.ScanResult
import com.cftester.scanner.ui.MainViewModel
import com.cftester.scanner.ui.UiState
import com.cftester.scanner.ui.export.ExportFormatter
import com.cftester.scanner.ui.export.ShareHelper
import com.cftester.scanner.ui.theme.*

@Composable
fun ResultsSection(viewModel: MainViewModel, state: UiState) {
    val context = LocalContext.current
    var exportMenuExpanded by remember { mutableStateOf(false) }

    val filteredResults = remember(state.workingResults, state.searchQuery) {
        if (state.searchQuery.isEmpty()) state.workingResults
        else state.workingResults.filter { it.ip.contains(state.searchQuery) || it.prefix.contains(state.searchQuery) }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .glassCard()
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("📋", modifier = Modifier.padding(end = 4.dp))
                Text(stringResource(R.string.results_table_title), fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color.White)
            }
            Surface(color = AccentGreen.copy(alpha = 0.2f), shape = RoundedCornerShape(4.dp)) {
                Text(
                    text = stringResource(R.string.results_count, filteredResults.size),
                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                    fontSize = 10.sp,
                    color = AccentGreen
                )
            }
        }

        // Search Filter and Bulk Actions
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = state.searchQuery,
                onValueChange = { viewModel.onSearchQueryChanged(it) },
                modifier = Modifier.weight(1f).height(48.dp),
                placeholder = { Text(stringResource(R.string.search_placeholder), fontSize = 10.sp) },
                singleLine = true
            )
            Button(
                onClick = { viewModel.copyAllIps(context) },
                colors = ButtonDefaults.buttonColors(containerColor = DarkBgSurface),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(stringResource(R.string.copy_all_ips), fontSize = 10.sp, color = AccentCyan)
            }
            Button(
                onClick = { viewModel.shareAllConfigs(context) },
                colors = ButtonDefaults.buttonColors(containerColor = DarkBgSurface),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(stringResource(R.string.share_all_configs), fontSize = 10.sp, color = AccentOrange)
            }

            // Export Dropdown
            Box {
                Button(
                    onClick = { exportMenuExpanded = true },
                    colors = ButtonDefaults.buttonColors(containerColor = DarkBgSurface),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(stringResource(R.string.export), fontSize = 10.sp, color = AccentBlue)
                }

                DropdownMenu(
                    expanded = exportMenuExpanded,
                    onDismissRequest = { exportMenuExpanded = false }
                ) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.export_ips), fontSize = 11.sp) },
                        onClick = {
                            exportMenuExpanded = false
                            val content = ExportFormatter.formatIpsTxt(state.workingResults)
                            if (content.isEmpty()) {
                                ShareHelper.shareText(context, "", title = context.getString(R.string.empty_export_error))
                            } else {
                                ShareHelper.shareCachedFile(context, "clean_ips.txt", "text/plain", content)
                            }
                        }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.export_configs), fontSize = 11.sp) },
                        onClick = {
                            exportMenuExpanded = false
                            val content = ExportFormatter.formatLinksTxt(state.workingResults)
                            if (content.isEmpty()) {
                                ShareHelper.shareText(context, "", title = context.getString(R.string.empty_export_error))
                            } else {
                                ShareHelper.shareCachedFile(context, "clean_configs.txt", "text/plain", content)
                            }
                        }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.export_csv), fontSize = 11.sp) },
                        onClick = {
                            exportMenuExpanded = false
                            val content = ExportFormatter.formatCsv(state.workingResults)
                            ShareHelper.shareCachedFile(context, "cloudflare_clean_ips.csv", "text/csv", content)
                        }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.export_json), fontSize = 11.sp) },
                        onClick = {
                            exportMenuExpanded = false
                            val content = ExportFormatter.formatJson(state.workingResults)
                            ShareHelper.shareCachedFile(context, "cloudflare_clean_ips.json", "application/json", content)
                        }
                    )
                }
            }
        }

        // Empty state vs Cards List
        if (filteredResults.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("🔍", fontSize = 28.sp)
                    Text(stringResource(R.string.no_results_title), color = TextSecondary, fontSize = 12.sp)
                    Text(stringResource(R.string.no_results_desc), color = TextMuted, fontSize = 10.sp)
                }
            }
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                filteredResults.forEachIndexed { index, result ->
                    ResultCard(index = index + 1, result = result, viewModel = viewModel)
                }
            }
        }
    }
}

@Composable
fun ResultCard(index: Int, result: ScanResult, viewModel: MainViewModel) {
    val context = LocalContext.current

    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = DarkBgSurface,
        shape = RoundedCornerShape(8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("#$index", fontSize = 10.sp, color = TextMuted)
                Column {
                    LtrText(
                        text = result.ip,
                        style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace),
                        color = Color.White
                    )
                    if (result.prefix.isNotEmpty()) {
                        LtrText(text = result.prefix, style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                    }
                }
            }

            // Latencies & Actions
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                // Google Ping Badge
                val pingColor = when {
                    result.googleLatencyMs <= 0 -> TextMuted
                    result.googleLatencyMs < 150f -> AccentGreen
                    result.googleLatencyMs < 300f -> AccentAmber
                    else -> AccentRed
                }
                Surface(color = pingColor.copy(alpha = 0.2f), shape = RoundedCornerShape(4.dp)) {
                    LtrText(
                        text = "${result.googleLatencyMs.toInt()} ms",
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        style = MaterialTheme.typography.labelSmall,
                        color = pingColor
                    )
                }

                // RealDelay Badge (if available)
                if (result.realDelayMs > 0) {
                    Surface(color = AccentCyan.copy(alpha = 0.2f), shape = RoundedCornerShape(4.dp)) {
                        LtrText(
                            text = "RD: ${result.realDelayMs.toInt()}ms",
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            style = MaterialTheme.typography.labelSmall,
                            color = AccentCyan
                        )
                    }
                }

                // Action buttons
                IconButton(onClick = { viewModel.copyIp(context, result.ip) }, modifier = Modifier.size(28.dp)) {
                    Text("📋", fontSize = 12.sp)
                }
                IconButton(onClick = { viewModel.copyConfig(context, result) }, modifier = Modifier.size(28.dp)) {
                    Text("🔗", fontSize = 12.sp)
                }
                IconButton(onClick = { viewModel.shareConfig(context, result) }, modifier = Modifier.size(28.dp)) {
                    Text("↗", fontSize = 12.sp)
                }
            }
        }
    }
}

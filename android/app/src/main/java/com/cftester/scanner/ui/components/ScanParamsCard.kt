package com.cftester.scanner.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cftester.scanner.R
import com.cftester.scanner.core.model.IpVersion
import com.cftester.scanner.core.model.SamplingMode
import com.cftester.scanner.ui.MainViewModel
import com.cftester.scanner.ui.UiState
import com.cftester.scanner.ui.theme.*

@Composable
fun ScanParamsCard(viewModel: MainViewModel, state: UiState) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .glassCard()
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("⚙️", modifier = Modifier.padding(end = 6.dp))
            Text(
                text = stringResource(R.string.scan_params_title),
                style = MaterialTheme.typography.titleMedium,
                color = Color.White
            )
        }

        // IP Version Toggle
        Column {
            Text(stringResource(R.string.lbl_ip_version), fontSize = 11.sp, color = TextSecondary)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                FilterChip(
                    selected = state.ipVersion == IpVersion.IPV4,
                    onClick = { viewModel.onIpVersionChanged(IpVersion.IPV4) },
                    label = { Text("IPv4", fontSize = 11.sp) }
                )
                FilterChip(
                    selected = state.ipVersion == IpVersion.IPV6,
                    onClick = { viewModel.onIpVersionChanged(IpVersion.IPV6) },
                    label = { Text("IPv6", fontSize = 11.sp) }
                )
                FilterChip(
                    selected = state.ipVersion == IpVersion.BOTH,
                    onClick = { viewModel.onIpVersionChanged(IpVersion.BOTH) },
                    label = { Text("Dual-Stack", fontSize = 11.sp) }
                )
            }
        }

        // Sampling Mode Dropdown
        Column {
            Text(stringResource(R.string.lbl_sample_mode), fontSize = 11.sp, color = TextSecondary)
            var expanded by remember { mutableStateOf(false) }
            val modes = listOf(
                SamplingMode.RANDOM to stringResource(R.string.opt_random),
                SamplingMode.GATEWAY_HOSTS to stringResource(R.string.opt_gateway),
                SamplingMode.STEP to stringResource(R.string.opt_step),
                SamplingMode.CUSTOM to stringResource(R.string.opt_custom)
            )
            Box {
                OutlinedButton(
                    onClick = { expanded = true },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(modes.firstOrNull { it.first == state.samplingMode }?.second ?: "", fontSize = 11.sp)
                }
                DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                    modes.forEach { (mode, title) ->
                        DropdownMenuItem(
                            text = { Text(title, fontSize = 11.sp) },
                            onClick = {
                                viewModel.onSamplingModeChanged(mode)
                                expanded = false
                            }
                        )
                    }
                }
            }
        }

        // Custom IPs input (if mode == CUSTOM)
        if (state.samplingMode == SamplingMode.CUSTOM) {
            OutlinedTextField(
                value = state.customIps,
                onValueChange = { viewModel.onCustomIpsChanged(it) },
                modifier = Modifier.fillMaxWidth().height(70.dp),
                placeholder = { Text(stringResource(R.string.custom_ips_placeholder), fontSize = 10.sp) }
            )
        }

        // Sliders Grid
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Column(modifier = Modifier.weight(1f)) {
                Text("${stringResource(R.string.lbl_ips_per_prefix)} ${state.ipsPerPrefix}", fontSize = 10.sp, color = TextSecondary)
                Slider(
                    value = state.ipsPerPrefix.toFloat(),
                    onValueChange = { viewModel.onIpsPerPrefixChanged(it.toInt()) },
                    valueRange = 1f..20f,
                    steps = 19
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text("${stringResource(R.string.lbl_max_ips)} ${state.maxIps}", fontSize = 10.sp, color = TextSecondary)
                Slider(
                    value = state.maxIps.toFloat(),
                    onValueChange = { viewModel.onMaxIpsChanged(it.toInt()) },
                    valueRange = 100f..5000f,
                    steps = 49
                )
            }
        }

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Column(modifier = Modifier.weight(1f)) {
                Text("${stringResource(R.string.lbl_concurrency)} ${state.concurrency}", fontSize = 10.sp, color = TextSecondary)
                Slider(
                    value = state.concurrency.toFloat(),
                    onValueChange = { viewModel.onConcurrencyChanged(it.toInt()) },
                    valueRange = 10f..200f,
                    steps = 19
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text("${stringResource(R.string.lbl_timeout)} ${state.timeoutMs / 1000f}s", fontSize = 10.sp, color = TextSecondary)
                Slider(
                    value = state.timeoutMs.toFloat(),
                    onValueChange = { viewModel.onTimeoutChanged(it.toLong()) },
                    valueRange = 1000f..5000f,
                    steps = 8
                )
            }
        }
    }
}

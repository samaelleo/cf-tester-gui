package com.cftester.scanner.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cftester.scanner.R
import com.cftester.scanner.ui.MainViewModel
import com.cftester.scanner.ui.UiState
import com.cftester.scanner.ui.theme.*

@Composable
fun ConfigInputCard(viewModel: MainViewModel, state: UiState) {
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
                Text("⚡", modifier = Modifier.padding(end = 6.dp))
                Text(
                    text = stringResource(R.string.config_input_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = Color.White
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Surface(
                    color = AccentBlue.copy(alpha = 0.2f),
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        text = state.parsedConfig.protocol.uppercase(),
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        fontSize = 10.sp,
                        color = AccentCyan
                    )
                }
                Surface(
                    color = if (state.parsedConfig.security == "tls") AccentGreen.copy(alpha = 0.2f) else DarkBgSurface,
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        text = if (state.parsedConfig.security == "tls") stringResource(R.string.tls_badge_on) else stringResource(R.string.tls_badge_off),
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        fontSize = 10.sp,
                        color = if (state.parsedConfig.security == "tls") AccentGreen else TextMuted
                    )
                }
            }
        }

        OutlinedTextField(
            value = state.configInput,
            onValueChange = { viewModel.onConfigInputChange(it) },
            modifier = Modifier
                .fillMaxWidth()
                .height(90.dp),
            placeholder = { Text(stringResource(R.string.config_placeholder), fontSize = 11.sp, color = TextMuted) },
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace, color = Color.White),
            maxLines = 4
        )

        // Parsed metadata chips row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            ChipItem(label = stringResource(R.string.lbl_sni), value = state.parsedConfig.getSniOrHost().ifEmpty { "auto" })
            ChipItem(label = stringResource(R.string.lbl_port), value = state.parsedConfig.port.toString())
            ChipItem(label = stringResource(R.string.lbl_transport), value = state.parsedConfig.transport)
            ChipItem(label = stringResource(R.string.lbl_path), value = state.parsedConfig.path)
        }
    }
}

@Composable
fun RowScope.ChipItem(label: String, value: String) {
    Surface(
        modifier = Modifier.weight(1f),
        color = DarkBgSurface,
        shape = RoundedCornerShape(6.dp)
    ) {
        Column(modifier = Modifier.padding(4.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text(label, fontSize = 9.sp, color = TextSecondary)
            LtrText(value, style = MaterialTheme.typography.labelSmall, color = Color.White)
        }
    }
}

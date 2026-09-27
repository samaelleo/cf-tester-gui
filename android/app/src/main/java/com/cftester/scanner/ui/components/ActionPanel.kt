package com.cftester.scanner.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cftester.scanner.R
import com.cftester.scanner.ui.MainViewModel
import com.cftester.scanner.ui.UiState
import com.cftester.scanner.ui.theme.*
import java.io.File

@Composable
fun ActionPanel(viewModel: MainViewModel, state: UiState) {
    val context = LocalContext.current

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        // Main action buttons (Start & RealDelay)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = { viewModel.startScan(context) },
                enabled = !state.isScanning,
                modifier = Modifier.weight(1.2f),
                colors = ButtonDefaults.buttonColors(containerColor = AccentBlue)
            ) {
                Text("▶ ${stringResource(R.string.start_scan)}", fontSize = 12.sp)
            }

            Button(
                onClick = {
                    val libDir = File(context.applicationInfo.nativeLibraryDir)
                    viewModel.startRealDelayTest(libDir, context.cacheDir)
                },
                enabled = state.workingResults.isNotEmpty() && !state.isTestingRealDelay,
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = AccentCyan, contentColor = Color.Black)
            ) {
                Text("⚡ ${stringResource(R.string.realdelay_btn)}", fontSize = 11.sp)
            }
        }

        // Secondary controls (Pause/Resume, Stop, Clear)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            OutlinedButton(
                onClick = {
                    if (state.isPaused) viewModel.resumeScan(context) else viewModel.pauseScan(context)
                },
                enabled = state.isScanning,
                modifier = Modifier.weight(1f)
            ) {
                Text(if (state.isPaused) stringResource(R.string.resume) else stringResource(R.string.pause), fontSize = 10.sp)
            }

            OutlinedButton(
                onClick = { viewModel.stopScan(context) },
                enabled = state.isScanning,
                colors = ButtonDefaults.outlinedButtonColors(contentColor = AccentRed),
                modifier = Modifier.weight(1f)
            ) {
                Text(stringResource(R.string.stop), fontSize = 10.sp)
            }

            TextButton(
                onClick = { viewModel.clearResults() },
                enabled = state.workingResults.isNotEmpty(),
                modifier = Modifier.weight(0.8f)
            ) {
                Text(stringResource(R.string.clear), fontSize = 10.sp, color = TextMuted)
            }
        }
    }
}

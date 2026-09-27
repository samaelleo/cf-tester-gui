package com.cftester.scanner.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cftester.scanner.R
import com.cftester.scanner.ui.MainViewModel
import com.cftester.scanner.ui.UiState
import com.cftester.scanner.ui.theme.*

@Composable
fun TopHeader(viewModel: MainViewModel, state: UiState) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .glassCard(shape = RoundedCornerShape(12.dp))
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                // Brand Logo Box with Cloudflare Orange/Blue Gradient
                Box(
                    modifier = Modifier
                        .size(34.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(BrandGradient),
                    contentAlignment = Alignment.Center
                ) {
                    Text("⚡", fontSize = 18.sp)
                }

                Column {
                    Text(
                        text = stringResource(R.string.scan_title),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                    Text(
                        text = stringResource(R.string.app_subtitle),
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextSecondary,
                        fontSize = 10.sp
                    )
                }
            }

            // Language Switch Button (EN / فارسی)
            Button(
                onClick = { viewModel.toggleLanguage() },
                colors = ButtonDefaults.buttonColors(containerColor = DarkBgSurface),
                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text(
                    text = if (state.isPersian) "EN" else "FA",
                    fontWeight = FontWeight.Bold,
                    color = AccentCyan
                )
            }
        }

        // ASN Pill Group
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            FilterChip(
                selected = state.selectedAsn == "13335",
                onClick = { viewModel.onAsnSelected("13335") },
                label = { Text("AS13335", fontSize = 11.sp) }
            )
            FilterChip(
                selected = state.selectedAsn == "209242",
                onClick = { viewModel.onAsnSelected("209242") },
                label = { Text("AS209242", fontSize = 11.sp) }
            )
            OutlinedTextField(
                value = state.customAsn,
                onValueChange = { viewModel.onCustomAsnChanged(it) },
                modifier = Modifier
                    .weight(1f)
                    .height(48.dp),
                textStyle = MaterialTheme.typography.bodyMedium.copy(color = Color.White),
                placeholder = { Text("ASN", fontSize = 11.sp) },
                singleLine = true
            )
            IconButton(
                onClick = { viewModel.fetchBgpPrefixes() },
                modifier = Modifier.size(36.dp)
            ) {
                Text("🔄", fontSize = 14.sp)
            }
            Surface(
                color = AccentBlue.copy(alpha = 0.2f),
                shape = RoundedCornerShape(6.dp)
            ) {
                Text(
                    text = stringResource(R.string.bgp_prefix_badge, state.bgpPrefixCount),
                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 4.dp),
                    fontSize = 10.sp,
                    color = AccentCyan
                )
            }
        }
    }
}

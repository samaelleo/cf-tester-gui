package com.cftester.scanner.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
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
            .glassCard(shape = RoundedCornerShape(14.dp))
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        // --- 1. Top Bar: Branding & Language Switcher ---
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                modifier = Modifier.weight(1f),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                // Brand Logo Box with Cloudflare Orange/Blue Gradient
                Box(
                    modifier = Modifier
                        .size(38.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(BrandGradient),
                    contentAlignment = Alignment.Center
                ) {
                    Text("⚡", fontSize = 20.sp)
                }

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.scan_title),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = stringResource(R.string.app_subtitle),
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary,
                        fontSize = 10.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Language Switch Button (EN / فارسی)
            Button(
                onClick = { viewModel.toggleLanguage() },
                colors = ButtonDefaults.buttonColors(containerColor = DarkBgSurface),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text(
                    text = if (state.isPersian) "EN" else "فارسی",
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp,
                    color = AccentCyan
                )
            }
        }

        HorizontalDivider(color = DarkBorder.copy(alpha = 0.5f), thickness = 1.dp)

        // --- 2. ASN Section Title + Live Prefix Count Badge ---
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = stringResource(R.string.asn_title),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = TextSecondary
            )

            // Prefix count badge with live status
            Surface(
                color = if (state.isFetchingBgp) AccentOrange.copy(alpha = 0.2f) else AccentBlue.copy(alpha = 0.2f),
                shape = RoundedCornerShape(6.dp)
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    if (state.isFetchingBgp) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(10.dp),
                            strokeWidth = 1.5.dp,
                            color = AccentOrange
                        )
                        Text(
                            text = stringResource(R.string.bgp_fetching),
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Medium,
                            color = AccentOrange
                        )
                    } else {
                        Text(
                            text = stringResource(R.string.bgp_prefix_badge, state.bgpPrefixCount),
                            fontSize = 10.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = AccentCyan
                        )
                    }
                }
            }
        }

        // --- 3. Preset ASN Chips (AS13335 vs AS209242) ---
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            val isAs13335 = state.selectedAsn == "13335"
            val isAs209242 = state.selectedAsn == "209242"

            FilterChip(
                selected = isAs13335,
                onClick = { viewModel.onAsnSelected("13335") },
                label = {
                    Text(
                        text = stringResource(R.string.btn_as13335),
                        fontSize = 11.sp,
                        fontWeight = if (isAs13335) FontWeight.Bold else FontWeight.Normal,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(8.dp),
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = AccentBlue.copy(alpha = 0.35f),
                    selectedLabelColor = Color.White,
                    containerColor = DarkBgSurface,
                    labelColor = TextSecondary
                ),
                border = FilterChipDefaults.filterChipBorder(
                    enabled = true,
                    selected = isAs13335,
                    borderColor = DarkBorder,
                    selectedBorderColor = AccentCyan
                )
            )

            FilterChip(
                selected = isAs209242,
                onClick = { viewModel.onAsnSelected("209242") },
                label = {
                    Text(
                        text = stringResource(R.string.btn_as209242),
                        fontSize = 11.sp,
                        fontWeight = if (isAs209242) FontWeight.Bold else FontWeight.Normal,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(8.dp),
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = AccentBlue.copy(alpha = 0.35f),
                    selectedLabelColor = Color.White,
                    containerColor = DarkBgSurface,
                    labelColor = TextSecondary
                ),
                border = FilterChipDefaults.filterChipBorder(
                    enabled = true,
                    selected = isAs209242,
                    borderColor = DarkBorder,
                    selectedBorderColor = AccentCyan
                )
            )
        }

        // --- 4. Custom ASN Input & Refresh Prefixes Button ---
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = state.customAsn,
                onValueChange = { viewModel.onCustomAsnChanged(it) },
                modifier = Modifier
                    .weight(1f)
                    .height(48.dp),
                textStyle = MaterialTheme.typography.bodyMedium.copy(
                    color = Color.White,
                    fontWeight = FontWeight.Medium
                ),
                placeholder = {
                    Text(
                        text = stringResource(R.string.custom_asn_placeholder),
                        fontSize = 11.sp,
                        color = TextMuted
                    )
                },
                leadingIcon = {
                    Text(
                        text = "#",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (state.selectedAsn !in listOf("13335", "209242")) AccentCyan else TextSecondary
                    )
                },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                shape = RoundedCornerShape(8.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = AccentCyan,
                    unfocusedBorderColor = if (state.selectedAsn !in listOf("13335", "209242")) AccentBlue else DarkBorder,
                    focusedContainerColor = DarkBgSurface,
                    unfocusedContainerColor = DarkBgSurface,
                    cursorColor = AccentCyan
                )
            )

            Button(
                onClick = { viewModel.fetchBgpPrefixes() },
                enabled = !state.isFetchingBgp,
                modifier = Modifier.height(48.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = AccentBlue,
                    disabledContainerColor = DarkBgSurface.copy(alpha = 0.5f)
                ),
                shape = RoundedCornerShape(8.dp),
                contentPadding = PaddingValues(horizontal = 14.dp, vertical = 0.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text("🔄", fontSize = 13.sp)
                    Text(
                        text = stringResource(R.string.fetch_bgp),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = Color.White
                    )
                }
            }
        }
    }
}

package com.cftester.scanner.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import com.cftester.scanner.ui.MainViewModel
import com.cftester.scanner.ui.theme.GlowBlue
import com.cftester.scanner.ui.theme.GlowOrange

@Composable
fun MainScreen(viewModel: MainViewModel) {
    val state by viewModel.uiState.collectAsState()

    Box(modifier = Modifier.fillMaxSize()) {
        // Ambient background glow 1 (Orange, top-right)
        Box(
            modifier = Modifier
                .size(300.dp)
                .offset(x = 100.dp, y = (-50).dp)
                .clip(CircleShape)
                .background(GlowOrange)
                .blur(80.dp)
        )
        // Ambient background glow 2 (Blue, bottom-left)
        Box(
            modifier = Modifier
                .size(350.dp)
                .offset(x = (-80).dp, y = 500.dp)
                .clip(CircleShape)
                .background(GlowBlue)
                .blur(80.dp)
        )

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
                .padding(horizontal = 14.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            item { TopHeader(viewModel = viewModel, state = state) }
            item { ConfigInputCard(viewModel = viewModel, state = state) }
            item { ScanParamsCard(viewModel = viewModel, state = state) }
            item { ActionPanel(viewModel = viewModel, state = state) }
            item { MetricsSummaryCard(state = state) }
            item { ResultsSection(viewModel = viewModel, state = state) }
        }
    }
}

package com.cftester.scanner.ui

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import com.cftester.scanner.ui.components.MainScreen
import com.cftester.scanner.ui.theme.CfTesterTheme
import com.cftester.scanner.ui.theme.DarkBgMain

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            val state by viewModel.uiState.collectAsState()

            LaunchedEffect(state.toastMessage) {
                state.toastMessage?.let { msg ->
                    Toast.makeText(this@MainActivity, msg, Toast.LENGTH_SHORT).show()
                    viewModel.clearToastMessage()
                }
            }

            CfTesterTheme(isPersian = state.isPersian) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = DarkBgMain
                ) {
                    MainScreen(viewModel = viewModel)
                }
            }
        }
    }
}

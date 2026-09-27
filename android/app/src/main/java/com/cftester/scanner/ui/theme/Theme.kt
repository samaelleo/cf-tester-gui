package com.cftester.scanner.ui.theme

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp

private val DarkColorScheme = darkColorScheme(
    primary = AccentBlue,
    onPrimary = Color.White,
    primaryContainer = AccentBlue.copy(alpha = 0.2f),
    onPrimaryContainer = Color.White,
    secondary = AccentCyan,
    onSecondary = Color.Black,
    secondaryContainer = AccentCyan.copy(alpha = 0.2f),
    onSecondaryContainer = Color.White,
    tertiary = AccentGreen,
    onTertiary = Color.Black,
    background = DarkBgMain,
    onBackground = TextPrimary,
    surface = DarkBgGlass,
    onSurface = TextPrimary,
    surfaceVariant = DarkBgSurface,
    onSurfaceVariant = TextSecondary,
    outline = GlassBorder,
    error = AccentRed,
    onError = Color.White
)

fun Modifier.glassCard(
    shape: Shape = RoundedCornerShape(12.dp),
    backgroundColor: Color = DarkBgGlass.copy(alpha = 0.82f),
    borderColor: Color = GlassBorder,
    borderWidth: Dp = 1.dp
): Modifier = this
    .clip(shape)
    .background(backgroundColor)
    .border(borderWidth, borderColor, shape)

val BrandGradient = Brush.linearGradient(
    colors = listOf(AccentOrange, AccentBlue)
)

val GlowOrange = Brush.radialGradient(
    colors = listOf(AccentOrange.copy(alpha = 0.2f), Color.Transparent)
)

val GlowBlue = Brush.radialGradient(
    colors = listOf(AccentBlue.copy(alpha = 0.18f), Color.Transparent)
)

@Composable
fun CfTesterTheme(
    isPersian: Boolean = false,
    content: @Composable () -> Unit
) {
    val layoutDirection = if (isPersian) LayoutDirection.Rtl else LayoutDirection.Ltr

    CompositionLocalProvider(LocalLayoutDirection provides layoutDirection) {
        MaterialTheme(
            colorScheme = DarkColorScheme,
            typography = AppTypography,
            content = content
        )
    }
}

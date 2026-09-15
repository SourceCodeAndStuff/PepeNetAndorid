package com.example.pepenet.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val PepeColors = darkColorScheme(
    primary = PepeGreen,
    onPrimary = SwampBg,
    secondary = PepeOlive,
    onSecondary = SwampBg,
    error = PepeRed,
    background = SwampBg,
    onBackground = SwampText,
    surface = SwampPanel,
    onSurface = SwampText,
    surfaceVariant = SwampInput,
    onSurfaceVariant = SwampDim,
    outline = Color(0xFF363A2C),
)

@Composable
fun PepeNetTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = PepeColors, typography = PepeTypography, content = content)
}

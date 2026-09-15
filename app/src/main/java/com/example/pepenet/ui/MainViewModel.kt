package com.example.pepenet.ui

import androidx.lifecycle.ViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

enum class ConnState { STOPPED, STARTING, RUNNING, ERROR }

data class UiState(
    val conn: ConnState = ConnState.STOPPED,
    val detail: String = "",
    val log: String = "",
    val caReady: Boolean = false,
    val caInstalled: Boolean = false,
    val caOutdated: Boolean = false,
    val caSteps: List<String> = emptyList(),
    val showCaGuide: Boolean = false,
    val message: String? = null,
)

class MainViewModel : ViewModel() {
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    fun onServiceStatus(state: String, detail: String, log: String) {
        val conn = when (state) {
            "running" -> ConnState.RUNNING
            "starting" -> ConnState.STARTING
            "error" -> ConnState.ERROR
            else -> ConnState.STOPPED
        }
        _state.update { it.copy(conn = conn, detail = detail, log = log) }
    }

    fun setConnecting() = _state.update { it.copy(conn = ConnState.STARTING, detail = "Starting…") }

    fun setCa(ready: Boolean, installed: Boolean, outdated: Boolean, steps: List<String>) =
        _state.update {
            it.copy(caReady = ready, caInstalled = installed, caOutdated = outdated, caSteps = steps,
                showCaGuide = if (installed) false else it.showCaGuide)
        }

    fun showCaGuide(show: Boolean) = _state.update { it.copy(showCaGuide = show) }

    fun showMessage(msg: String?) = _state.update { it.copy(message = msg) }
}

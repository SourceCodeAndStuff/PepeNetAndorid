package com.example.pepenet

import com.example.pepenet.ui.ConnState
import com.example.pepenet.ui.MainViewModel
import org.junit.Assert.assertEquals
import org.junit.Test

class ExampleUnitTest {
    @Test
    fun serviceStatusMapsToUiState() {
        val vm = MainViewModel()
        vm.onServiceStatus("running", "block 1200000", "")
        assertEquals(ConnState.RUNNING, vm.state.value.conn)
        vm.onServiceStatus("stopped", "", "")
        assertEquals(ConnState.STOPPED, vm.state.value.conn)
    }
}

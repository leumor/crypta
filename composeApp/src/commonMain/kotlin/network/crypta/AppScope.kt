package network.crypta

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel

/**
 * Provides a lifecycle-aware coroutine scope for the application.
 */
object AppScope {
    private var _scope: CoroutineScope? = null

    /** Returns the background scope. Requires [start] to be called first. */
    val scope: CoroutineScope
        get() = _scope ?: error("App scope not started")

    /** Starts the background scope if it is not already running. */
    fun start() {
        if (_scope == null) {
            _scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        }
    }

    /** Cancels the background scope if it has been started. */
    fun cancel() {
        _scope?.cancel()
        _scope = null
    }
}

// Helper functions for Swift interop
fun startAppScope() = AppScope.start()
fun cancelAppScope() = AppScope.cancel()


package network.crypta

import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.window.ComposeViewport
import kotlinx.browser.document
import kotlinx.browser.window
import network.crypta.startAppScope
import network.crypta.cancelAppScope

@OptIn(ExperimentalComposeUiApi::class)
fun main() {
    startAppScope()
    ComposeViewport(document.body!!) {
        App()
    }
    window.addEventListener("beforeunload", {
        cancelAppScope()
    })
}
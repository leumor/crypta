package network.crypta

import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import network.crypta.startAppScope
import network.crypta.cancelAppScope

fun main() = application {
    startAppScope()
    Window(
        onCloseRequest = {
            cancelAppScope()
            exitApplication()
        },
        title = "Crypta",
    ) {
        App()
    }
}
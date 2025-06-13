package network.crypta

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.ui.tooling.preview.Preview
import network.crypta.startAppScope
import network.crypta.cancelAppScope

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        startAppScope()

        setContent {
            App()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        cancelAppScope()
    }
}

@Preview
@Composable
fun AppAndroidPreview() {
    App()
}
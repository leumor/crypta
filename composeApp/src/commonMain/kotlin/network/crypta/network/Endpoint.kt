package network.crypta.network

import com.eygraber.uri.Uri

// Endpoint is named Peer in Fred
interface Endpoint {
    val uri: Uri
}

data class UdpEndPoint(override val uri: Uri) : Endpoint {
    val host = uri.host
    val port = uri.port

    init {
        require(uri.scheme == "udp") {
            "URI scheme must be 'udp'"
        }
    }
}
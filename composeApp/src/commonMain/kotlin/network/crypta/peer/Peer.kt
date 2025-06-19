package network.crypta.peer

import network.crypta.network.Endpoint

// Peer is named PeerNode in Fred
interface Peer {
    val endpoint: Endpoint
    val version: String

}
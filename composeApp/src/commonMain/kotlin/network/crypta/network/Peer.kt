package network.crypta.network

interface PeerContext

data class Peer(val host: HostInfo, val port: Int) {
}
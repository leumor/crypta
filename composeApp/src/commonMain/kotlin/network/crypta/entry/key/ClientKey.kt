package network.crypta.entry.key

import network.crypta.crypto.CryptoAlgorithm

abstract class ClientKey(
    routingKey: RoutingKey,
    sharedKey: SharedKey?,
    cryptoAlgorithm: CryptoAlgorithm,
    metaStrings: MutableList<String>
) : AccessKey(routingKey, sharedKey, cryptoAlgorithm, metaStrings) {

}

class ClientChk(
    routingKey: RoutingKey,
    sharedKey: SharedKey?,
    cryptoAlgorithm: CryptoAlgorithm,
    fileName: String,
    val isControlDocument: Boolean,
    val compressionAlgorithm: CompressionAlgorithm
) : ClientKey(routingKey, sharedKey, cryptoAlgorithm, mutableListOf()) {
    init {
        metaStrings.add(fileName)
    }
}

class ClientSsk(
    routingKey: RoutingKey,
    sharedKey: SharedKey,
    cryptoAlgorithm: CryptoAlgorithm,
    metaStrings: MutableList<String>,
)
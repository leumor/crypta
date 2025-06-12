package network.crypta.entry.key

import network.crypta.crypto.CryptoAlgorithm
import network.crypta.crypto.DsaPublicKey
import network.crypta.crypto.Hash
import network.crypta.crypto.HashAlgorithm
import network.crypta.entry.RoutingKey

interface NodeKey

class NodeChk(routingKey: RoutingKey, cryptoAlgorithm: CryptoAlgorithm) :
    NodeKey, Key by BasicKey(routingKey, cryptoAlgorithm) {

}

class NodeSsk(
    val clientRoutingKey: RoutingKey,
    cryptoAlgorithm: CryptoAlgorithm,
    val ehDocName: ByteArray,
    val publicKey: DsaPublicKey? = null,
) : NodeKey,
    Key by BasicKey(makeNodeRoutingKey(clientRoutingKey, ehDocName), cryptoAlgorithm) {

    init {
        if (publicKey != null) {
            val pubKeyHash = Hash.digest(HashAlgorithm.SHA256, publicKey.bytes)
            require(pubKeyHash.contentEquals(clientRoutingKey.bytes)) {
                "Invalid pubKey: wrong hash"
            }
        }

        require(ehDocName.size == EH_DOC_NAME_SIZE) {
            "EH doc name must be $EH_DOC_NAME_SIZE bytes"
        }
    }

    companion object {
        const val EH_DOC_NAME_SIZE = 32

        private fun makeNodeRoutingKey(
            clientRoutingKey: RoutingKey,
            ehDocName: ByteArray
        ): RoutingKey {
            val hasher = Hash.hasher(HashAlgorithm.SHA256)
            hasher.update(ehDocName)
            hasher.update(clientRoutingKey.bytes)
            return RoutingKey(hasher.digest())
        }

    }
}

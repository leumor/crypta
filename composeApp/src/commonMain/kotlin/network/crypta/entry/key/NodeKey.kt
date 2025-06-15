package network.crypta.entry.key

import network.crypta.crypto.CryptoAlgorithm
import network.crypta.crypto.DsaPublicKey
import network.crypta.crypto.Hash
import network.crypta.crypto.HashAlgorithm
import network.crypta.entry.RoutingKey

interface NodeKey

data class NodeChk(
    override val routingKey: RoutingKey,
    override val cryptoAlgorithm: CryptoAlgorithm
) : NodeKey, Key by BasicKey(routingKey, cryptoAlgorithm) {

    companion object {
        /** Base type identifier for a CHK stored on a node. */
        const val BASE_TYPE: Byte = 1
    }

    /**
     * Get key type.
     *
     * High 8 bit of the returned value contains the base type while the
     * low 8 bit stores the crypto algorithm identifier.
     */
    fun getType(): Short =
        ((BASE_TYPE.toInt() shl 8) + (cryptoAlgorithm.value and 0xFF)).toShort()
}

data class NodeSsk(
    val clientRoutingKey: RoutingKey,
    override val cryptoAlgorithm: CryptoAlgorithm,
    val ehDocName: ByteArray,
    val publicKey: DsaPublicKey? = null,
) : NodeKey, Key by BasicKey(makeNodeRoutingKey(clientRoutingKey, ehDocName), cryptoAlgorithm) {

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

    /**
     * Get key type.
     *
     * High 8 bits contain the base type ([BASE_TYPE]) while the low 8 bits store
     * the crypto algorithm identifier.
     */
    fun getType(): Short =
        ((BASE_TYPE.toInt() shl 8) + (cryptoAlgorithm.value and 0xFF)).toShort()

    companion object {
        /** Base type identifier for an SSK stored on a node. */
        const val BASE_TYPE: Byte = 2

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

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as NodeSsk

        if (clientRoutingKey != other.clientRoutingKey) return false
        if (cryptoAlgorithm != other.cryptoAlgorithm) return false
        if (!ehDocName.contentEquals(other.ehDocName)) return false
        if (publicKey != other.publicKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = clientRoutingKey.hashCode()
        result = 31 * result + cryptoAlgorithm.hashCode()
        result = 31 * result + ehDocName.contentHashCode()
        result = 31 * result + (publicKey?.hashCode() ?: 0)
        return result
    }
}

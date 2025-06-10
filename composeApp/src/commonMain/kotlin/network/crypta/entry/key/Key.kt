package network.crypta.entry.key

import network.crypta.crypto.CryptoAlgorithm
import network.crypta.crypto.SecretKey
import kotlin.jvm.JvmInline

const val ROUTING_KEY_SIZE = 32


@JvmInline
value class RoutingKey(val bytes: ByteArray) {
    init {
        require(bytes.size == ROUTING_KEY_SIZE) {
            "Routing key must be $ROUTING_KEY_SIZE bytes"
        }
    }
}

typealias SharedKey = SecretKey

enum class CompressionAlgorithm(val value: Int) {
    NO_COMP(-1),
    GZIP(0),
    BZIP2(1),
    LZMA(3);


    companion object {
        private val byValue: Map<Int, CompressionAlgorithm> =
            CompressionAlgorithm.entries.associateBy(CompressionAlgorithm::value)

        fun fromValue(value: Int): CompressionAlgorithm =
            byValue[value] ?: error("Unknown value: $value")
    }
}

sealed class Key(val routingKey: RoutingKey, val cryptoAlgorithm: CryptoAlgorithm)
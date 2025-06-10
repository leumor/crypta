package network.crypta.entry.key

import network.crypta.crypto.CryptoAlgorithm
import kotlin.jvm.JvmInline

const val ROUTING_KEY_SIZE = 32
const val SHARED_KEY_SIZE = 32


@JvmInline
value class RoutingKey(val bytes: ByteArray) {
    init {
        require(bytes.size == ROUTING_KEY_SIZE) {
            "Routing key must be $ROUTING_KEY_SIZE bytes"
        }
    }
}

@JvmInline
value class SharedKey(val bytes: ByteArray) {
    init {
        require(bytes.size == SHARED_KEY_SIZE) {
            "Decryption key must be $SHARED_KEY_SIZE bytes"
        }
    }
}

enum class CompressionAlgorithm(val value: Int) {
    NO_COMP(-1),
    GZIP(0),
    BZIP2(1),
    LZMA(3),
}

sealed class Key(val routingKey: RoutingKey, val cryptoAlgorithm: CryptoAlgorithm)
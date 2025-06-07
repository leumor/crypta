package network.crypta.entry.key

import kotlin.jvm.JvmInline

const val ROUTING_KEY_SIZE = 32
const val DECRYPTION_KEY_SIZE = 32


@JvmInline
value class RoutingKey(val bytes: ByteArray) {
    init {
        require(bytes.size == ROUTING_KEY_SIZE) {
            "Routing key must be $ROUTING_KEY_SIZE bytes"
        }
    }
}

@JvmInline
value class DecryptionKey(val bytes: ByteArray) {
    init {
        require(bytes.size == DECRYPTION_KEY_SIZE) {
            "Decryption key must be $DECRYPTION_KEY_SIZE bytes"
        }
    }
}

enum class CryptoAlgorithm(val value: Int) {
    AES_PCFB_256_SHA256(2),
    AES_CTR_256_SHA256(3),
}

enum class CompressionAlgorithm(val value: Int) {
    NO_COMP(-1),
    GZIP(0),
    BZIP2(1),
    LZMA(3),
}

sealed class Key(val routingKey: RoutingKey, val cryptoAlgorithm: CryptoAlgorithm)
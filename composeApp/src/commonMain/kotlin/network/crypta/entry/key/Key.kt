package network.crypta.entry.key

import network.crypta.crypto.CryptoAlgorithm
import network.crypta.entry.RoutingKey

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
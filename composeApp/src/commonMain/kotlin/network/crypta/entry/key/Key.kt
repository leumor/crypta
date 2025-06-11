package network.crypta.entry.key

import network.crypta.crypto.CryptoAlgorithm
import network.crypta.entry.RoutingKey

/**
 * Enumerates the supported compression algorithms for data within Crypta network.
 *
 * @property value The integer identifier for the compression algorithm.
 */
enum class CompressionAlgorithm(val value: Int) {
    /** No compression is applied. */
    NO_COMP(-1),

    /** Gzip compression. */
    GZIP(0),

    /** Bzip2 compression. */
    BZIP2(1),

    /** LZMA compression. */
    LZMA(3);


    companion object {
        private val byValue: Map<Int, CompressionAlgorithm> =
            CompressionAlgorithm.entries.associateBy(CompressionAlgorithm::value)

        /**
         * Retrieves a [CompressionAlgorithm] from its integer value.
         * @param value The integer representation of the algorithm.
         * @return The corresponding [CompressionAlgorithm].
         * @throws IllegalStateException if the value is unknown.
         */
        fun fromValue(value: Int): CompressionAlgorithm =
            byValue[value] ?: error("Unknown value: $value")
    }
}

/**
 * Represents a base Crypta key. A key is a type of URI used to access data on the network.
 * All key types are derived from this sealed class.
 *
 * @property routingKey The key used to locate the data in the Crypta network. It is typically a hash.
 * @property cryptoAlgorithm The cryptographic algorithm used to encrypt the content.
 */
sealed class Key(val routingKey: RoutingKey, val cryptoAlgorithm: CryptoAlgorithm)
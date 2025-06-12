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
 * Base contract for all Crypta keys.
 *
 * Implementations should simply provide the routing key and the crypto
 * algorithm used. The common behaviour can then be delegated to
 * [BasicKey] to reduce boilerplate.
 */
sealed interface Key {
    val routingKey: RoutingKey
    val cryptoAlgorithm: CryptoAlgorithm
}

/**
 * Simple [Key] implementation that stores the required properties. Other
 * classes in the hierarchy delegate to this data class.
 */
data class BasicKey(
    override val routingKey: RoutingKey,
    override val cryptoAlgorithm: CryptoAlgorithm
) : Key

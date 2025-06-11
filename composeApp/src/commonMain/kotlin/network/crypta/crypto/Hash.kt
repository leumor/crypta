package network.crypta.crypto

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.SHA1
import dev.whyoleg.cryptography.algorithms.SHA256

/**
 * Enumerates the supported cryptographic hash algorithms.
 */
enum class HashAlgorithm {
    /** The SHA-1 hash algorithm, producing a 160-bit hash. */
    SHA1,

    /** The SHA-256 hash algorithm, producing a 256-bit hash. */
    SHA256,
}

/**
 * A utility object for computing cryptographic hashes.
 *
 * Provides methods for both one-shot hashing of a complete byte array and
 * stateful hashing for chunked or streaming data.
 */
object Hash {
    /**
     * Computes the hash of a byte array in a single operation.
     *
     * @param algorithm The [HashAlgorithm] to use (e.g., SHA-1, SHA-256).
     * @param data The input data to hash.
     * @return The resulting hash digest as a [ByteArray].
     */
    @OptIn(DelicateCryptographyApi::class)
    fun digest(algorithm: HashAlgorithm, data: ByteArray): ByteArray {
        val algo = when (algorithm) {
            HashAlgorithm.SHA1 -> SHA1
            HashAlgorithm.SHA256 -> SHA256
        }
        return CryptographyProvider.Default
            .get(algo)
            .hasher()
            .hashBlocking(data)
    }

    /**
     * Creates a stateful [Hasher] instance for a given algorithm.
     *
     * This is useful for hashing large amounts of data in chunks without holding
     * all the data in memory at once.
     *
     * @param algorithm The [HashAlgorithm] to use.
     * @return A new [Hasher] instance.
     */
    @OptIn(DelicateCryptographyApi::class)
    fun hasher(algorithm: HashAlgorithm): Hasher {
        val algo = when (algorithm) {
            HashAlgorithm.SHA1 -> SHA1
            HashAlgorithm.SHA256 -> SHA256
        }
        val function = CryptographyProvider.Default
            .get(algo)
            .hasher()
            .createHashFunction()
        return Hasher(function)
    }
}

/**
 * A stateful hash computer.
 *
 * Allows for data to be updated in chunks and then produces a final digest.
 * An instance of [Hasher] is not thread-safe.
 *
 * @param fn The underlying hash function from the cryptography provider.
 */
class Hasher internal constructor(
    private val fn: dev.whyoleg.cryptography.operations.HashFunction,
) {
    /**
     * Updates the hash computation with a chunk of data.
     *
     * @param data The byte array containing the data to add.
     * @param offset The starting offset within the [data] array.
     * @param length The number of bytes to process from the [data] array.
     */
    fun update(data: ByteArray, offset: Int = 0, length: Int = data.size) {
        fn.update(data, offset, length)
    }

    /**
     * Finalizes the hash computation and returns the digest.
     *
     * After this method is called, the hasher is automatically reset and can be
     * used to compute a new hash.
     *
     * @return The computed hash digest as a [ByteArray].
     */
    fun digest(): ByteArray {
        val out = fn.hashToByteArray()
        fn.reset()
        return out
    }
}

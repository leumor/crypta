package network.crypta.crypto

import dev.whyoleg.cryptography.random.CryptographyRandom
import kotlin.jvm.JvmInline

const val SECRET_KEY_SIZE = 32

@JvmInline
value class SecretKey(val bytes: ByteArray) {
    init {
        require(bytes.size == SECRET_KEY_SIZE) {
            "Secret key must be $SECRET_KEY_SIZE bytes"
        }
    }
}

enum class CryptoAlgorithm(val value: Int) {
    AES_PCFB_256_SHA256(2),
    AES_CTR_256_SHA256(3),
}

/**
 * An interface for symmetric ciphers used in the Crypta network.
 *
 * This interface provides a standardized way to perform cryptographic operations,
 * supporting both one-shot processing for small data and stateful streaming for large data.
 * Implementations are expected to be thread-safe for one-shot operations, but the
 * returned [CryptoCipherStream] instances are stateful and not thread-safe.
 */
interface CryptoCipher {
    /**
     * Encrypts the given plaintext data in a single operation.
     *
     * @param iv The initialization vector. Must be unique for each encryption with the same key.
     *           Its required length depends on the specific cipher implementation.
     * @param data The plaintext data to encrypt.
     * @return The resulting ciphertext.
     */
    fun encrypt(iv: ByteArray, data: ByteArray): ByteArray

    /**
     * Decrypts the given ciphertext data in a single operation.
     *
     * @param iv The initialization vector that was used for encryption.
     * @param data The ciphertext data to decrypt.
     * @return The resulting plaintext.
     */
    fun decrypt(iv: ByteArray, data: ByteArray): ByteArray

    /**
     * Creates a new stateful stream for encrypting data in chunks.
     *
     * Each call to this method returns a new, independent stream instance initialized
     * with the given [iv]. The returned stream is not thread-safe.
     *
     * @param iv The initialization vector. Must be unique for each encryption stream with the same key.
     * @return A [CryptoCipherStream] for performing encryption.
     */
    fun encryptor(iv: ByteArray): CryptoCipherStream

    /**
     * Creates a new stateful stream for decrypting data in chunks.
     *
     * Each call to this method returns a new, independent stream instance initialized
     * with the given [iv]. The returned stream is not thread-safe.
     *
     * @param iv The initialization vector that was used for encryption.
     * @return A [CryptoCipherStream] for performing decryption.
     */
    fun decryptor(iv: ByteArray): CryptoCipherStream

    /**
     * A factory for creating [CryptoCipher] instances.
     */
    companion object {
        /**
         * Creates a [CryptoCipher] instance for the specified algorithm and key.
         *
         * @param algorithm The [CryptoAlgorithm] to use.
         * @param key The raw symmetric key bytes. The required length depends on the algorithm.
         * @return A new [CryptoCipher] instance.
         * @throws IllegalArgumentException if the provided [algorithm] is not supported.
         */
        fun create(algorithm: CryptoAlgorithm, key: ByteArray): CryptoCipher = when (algorithm) {
            CryptoAlgorithm.AES_PCFB_256_SHA256 -> Rijndael256Cipher(key)
            CryptoAlgorithm.AES_CTR_256_SHA256 -> AesCtrCipher(key)
        }

        /**
         * Generates a new 256-bit [SecretKey] using the default cryptographic random source.
         */
        fun generateSecretKey(random: CryptographyRandom = CryptographyRandom.Default): SecretKey {
            val bytes = ByteArray(SECRET_KEY_SIZE)
            random.nextBytes(bytes)
            return SecretKey(bytes)
        }
    }
}

/**
 * A stateful stream for chunk-based cryptographic processing.
 *
 * This interface is used by [CryptoCipher] to handle encryption or decryption of data
 * that arrives in segments, such as from a network stream or a large file.
 * Instances of this stream are not thread-safe.
 */
interface CryptoCipherStream {
    fun update(data: ByteArray, offset: Int = 0, length: Int = data.size): ByteArray
}

package network.crypta.crypto

/**
 * An implementation of [CryptoCipher] using a custom [Rijndael256] engine in PCFB mode.
 *
 * PCFB (Propagating Cipher Feedback) is a stream cipher mode of operation. This class
 * wraps a [Rijndael256] engine to provide the [CryptoCipher] interface.
 *
 * Note: The underlying [Rijndael256] engine is stateful for streaming operations.
 * One-shot methods are safe, but a single [Rijndael256Cipher] instance should not be
 * used for multiple concurrent streaming operations. New streams should be created via
 * [encryptor] and [decryptor] for each concurrent task.
 *
 * @property key The raw key bytes for the Rijndael-256 algorithm.
 * @constructor Creates a `Rijndael256Cipher` with the given key.
 */
internal class Rijndael256Cipher(key: ByteArray) : CryptoCipher {
    /**
     * The underlying stateful [Rijndael256] engine instance.
     * This engine holds the key and the state for CFB mode operations.
     */
    private val engine = Rijndael256(key)

    /**
     * Encrypts data using the stateful engine's PCFB mode in a single operation.
     * The engine's internal state is initialized with the [iv] for this operation.
     */
    override fun encrypt(iv: ByteArray, data: ByteArray): ByteArray =
        engine.encryptCfb(data, iv)

    /**
     * Decrypts data using the stateful engine's PCFB mode in a single operation.
     * The engine's internal state is initialized with the [iv] for this operation.
     */
    override fun decrypt(iv: ByteArray, data: ByteArray): ByteArray =
        engine.decryptCfb(data, iv)

    /**
     * Creates a new stateful stream for encrypting data in chunks using PCFB mode.
     *
     * This method first resets the internal state of the [engine] with the provided [iv],
     * then returns a [CryptoCipherStream] that will process subsequent data chunks.
     *
     * @param iv The initialization vector for the CFB stream.
     * @return A new [CryptoCipherStream] for encryption.
     */
    override fun encryptor(iv: ByteArray): CryptoCipherStream {
        engine.resetCfb(iv)
        return object : CryptoCipherStream {
            override fun update(data: ByteArray, offset: Int, length: Int): ByteArray =
                engine.encryptCfb(data, offset, length)
        }
    }

    /**
     * Creates a new stateful stream for decrypting data in chunks using PCFB mode.
     *
     * This method first resets the internal state of the [engine] with the provided [iv],
     * then returns a [CryptoCipherStream] that will process subsequent data chunks.
     *
     * @param iv The initialization vector for the CFB stream.
     * @return A new [CryptoCipherStream] for decryption.
     */
    override fun decryptor(iv: ByteArray): CryptoCipherStream {
        engine.resetCfb(iv)
        return object : CryptoCipherStream {
            override fun update(data: ByteArray, offset: Int, length: Int): ByteArray =
                engine.decryptCfb(data, offset, length)
        }
    }
}

package network.crypta.crypto

import network.crypta.entry.key.CryptoAlgorithm

/**
 * Basic interface for symmetric ciphers used in Crypta.
 * It provides one-shot encryption/decryption and streaming capabilities.
 */
interface CryptoCipher {
    /** Encrypt [data] using the provided [iv]. */
    fun encrypt(iv: ByteArray, data: ByteArray): ByteArray

    /** Decrypt [data] using the provided [iv]. */
    fun decrypt(iv: ByteArray, data: ByteArray): ByteArray

    /** Start streaming encryption with the specified [iv]. */
    fun encryptor(iv: ByteArray): CryptoCipherStream

    /** Start streaming decryption with the specified [iv]. */
    fun decryptor(iv: ByteArray): CryptoCipherStream

    companion object {
        /** Create a cipher for the given [algorithm] using raw [key] bytes. */
        fun create(algorithm: CryptoAlgorithm, key: ByteArray): CryptoCipher = when (algorithm) {
            CryptoAlgorithm.AES_PCFB_256_SHA256 -> Rijndael256Cipher(key)
            CryptoAlgorithm.AES_CTR_256_SHA256 -> AesCtrCipher(key)
        }
    }
}

/** Simple stream interface used by [CryptoCipher]. */
interface CryptoCipherStream {
    fun update(data: ByteArray, offset: Int = 0, length: Int = data.size): ByteArray
}

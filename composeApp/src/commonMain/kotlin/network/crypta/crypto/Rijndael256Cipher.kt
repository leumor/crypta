package network.crypta.crypto

/** Implementation of [CryptoCipher] using [Rijndael256] in PCFB mode. */
internal class Rijndael256Cipher(key: ByteArray) : CryptoCipher {
    private val engine = Rijndael256(key)

    override fun encrypt(iv: ByteArray, data: ByteArray): ByteArray =
        engine.encryptCfb(data, iv)

    override fun decrypt(iv: ByteArray, data: ByteArray): ByteArray =
        engine.decryptCfb(data, iv)

    override fun encryptor(iv: ByteArray): CryptoCipherStream {
        engine.resetCfb(iv)
        return object : CryptoCipherStream {
            override fun update(data: ByteArray, offset: Int, length: Int): ByteArray =
                engine.encryptCfb(data, offset, length)
        }
    }

    override fun decryptor(iv: ByteArray): CryptoCipherStream {
        engine.resetCfb(iv)
        return object : CryptoCipherStream {
            override fun update(data: ByteArray, offset: Int, length: Int): ByteArray =
                engine.decryptCfb(data, offset, length)
        }
    }
}

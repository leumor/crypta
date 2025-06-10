package network.crypta.crypto

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

@OptIn(ExperimentalStdlibApi::class)
class CryptoCipherTest {
    private val ctrKey =
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".hexToByteArray()
    private val ctrIv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".hexToByteArray()
    private val ctrPlaintext = (
            "6bc1bee22e409f96e93d7e117393172a" +
                    "ae2d8a571e03ac9c9eb76fac45af8e51" +
                    "30c81c46a35ce411e5fbc1191a0a52ef" +
                    "f69f2445df4f9b17ad2b417be66c3710"
            ).hexToByteArray()
    private val ctrCiphertext = (
            "601ec313775789a5b7a7f504bbf3d228" +
                    "f443e3ca4d62b59aca84e990cacaf5c5" +
                    "2b0930daa23de94ce87017ba2d84988d" +
                    "dfc9c58db67aada613c2dd08457941a6"
            ).hexToByteArray()

    private val pcfbKey = ctrKey
    private val pcfbIv = (
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" +
                    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
            ).hexToByteArray()
    private val pcfbPlaintext = ctrPlaintext
    private val pcfbCiphertext = (
            "c964b00326e216214f1a68f5b0872608" +
                    "1b403c92fe02898664a81f5bbbbf8341" +
                    "fc1d04b2c1addfb826cca1eab6813127" +
                    "2751b9d6cd536f78059b10b4867dbbd9"
            ).hexToByteArray()

    @Test
    fun testGenerateSecretKey() {
        val key = CryptoCipher.generateSecretKey()
        assertEquals(SECRET_KEY_SIZE, key.bytes.size)
    }

    @Test
    fun testAesCtrKnownValues() {
        val cipher = CryptoCipher.create(CryptoAlgorithm.AES_CTR_256_SHA256, ctrKey)
        val enc = cipher.encrypt(ctrIv, ctrPlaintext)
        assertContentEquals(ctrCiphertext, enc)
        val dec = cipher.decrypt(ctrIv, enc)
        assertContentEquals(ctrPlaintext, dec)
    }

    @Test
    fun testAesCtrStreamingRandom() {
        val cipher = CryptoCipher.create(CryptoAlgorithm.AES_CTR_256_SHA256, ctrKey)
        val encStream = cipher.encryptor(ctrIv)
        var offset = 0
        var out = ByteArray(0)
        while (offset < ctrPlaintext.size) {
            val max = ctrPlaintext.size - offset
            val count = if (max == 1) 1 else Random.nextInt(1, max)
            out += encStream.update(ctrPlaintext, offset, count)
            offset += count
        }
        assertContentEquals(ctrCiphertext, out)

        val decStream = cipher.decryptor(ctrIv)
        offset = 0
        var plainOut = ByteArray(0)
        while (offset < out.size) {
            val max = out.size - offset
            val count = if (max == 1) 1 else Random.nextInt(1, max)
            plainOut += decStream.update(out, offset, count)
            offset += count
        }
        assertContentEquals(ctrPlaintext, plainOut)
    }

    @Test
    fun testPcfbOneShot() {
        val cipher = CryptoCipher.create(CryptoAlgorithm.AES_PCFB_256_SHA256, pcfbKey)
        val enc = cipher.encrypt(pcfbIv, pcfbPlaintext)
        assertContentEquals(pcfbCiphertext, enc)
        val dec = cipher.decrypt(pcfbIv, enc)
        assertContentEquals(pcfbPlaintext, dec)
    }

    @Test
    fun testPcfbStreamingRandom() {
        val cipher = CryptoCipher.create(CryptoAlgorithm.AES_PCFB_256_SHA256, pcfbKey)
        val encStream = cipher.encryptor(pcfbIv)
        var offset = 0
        var out = ByteArray(0)
        while (offset < pcfbPlaintext.size) {
            val max = pcfbPlaintext.size - offset
            val count = if (max == 1) 1 else Random.nextInt(1, max)
            out += encStream.update(pcfbPlaintext, offset, count)
            offset += count
        }
        assertContentEquals(pcfbCiphertext, out)

        val decStream = cipher.decryptor(pcfbIv)
        offset = 0
        var plainOut = ByteArray(0)
        while (offset < out.size) {
            val max = out.size - offset
            val count = if (max == 1) 1 else Random.nextInt(1, max)
            plainOut += decStream.update(out, offset, count)
            offset += count
        }
        assertContentEquals(pcfbPlaintext, plainOut)
    }
}

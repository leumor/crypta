package network.crypta.crypto

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals


@OptIn(ExperimentalStdlibApi::class)
class Rijndael256Test {
    val plaintext256 =
        "0123456789abcdef1123456789abcdef2123456789abcdef3123456789abcdef".hexToByteArray()
    val key256 = "deadbeefcafebabe0123456789abcdefcafebabedeadbeefcafebabe01234567".hexToByteArray()
    val cipher256 =
        "6fcbc68fc938e5f5a7c24d7422f4b5f153257b6fb53e0bca26770497dd65078c".hexToByteArray()


    val pcfb256EncryptKey =
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".hexToByteArray()
    val pcfb256EncryptIv =
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".hexToByteArray()
    val pcfb256EncryptPlaintext = ("6bc1bee22e409f96e93d7e117393172a"
            + "ae2d8a571e03ac9c9eb76fac45af8e51"
            + "30c81c46a35ce411e5fbc1191a0a52ef"
            + "f69f2445df4f9b17ad2b417be66c3710").hexToByteArray()
    val pcfb256EncryptCiphertext = ("c964b00326e216214f1a68f5b0872608"
            + "1b403c92fe02898664a81f5bbbbf8341"
            + "fc1d04b2c1addfb826cca1eab6813127"
            + "2751b9d6cd536f78059b10b4867dbbd9").hexToByteArray()

    val pcfb256DecryptKey = pcfb256EncryptKey
    val pcfb256DecryptIv = pcfb256EncryptIv
    val pcfb256DecryptPlaintext = pcfb256EncryptPlaintext
    val pcfb256DecryptCiphertext = pcfb256EncryptCiphertext

    @Test
    fun testKnownValues() {
        val cipher = Rijndael256(key256)
        val encrypted = cipher.encrypt(plaintext256)
        assertContentEquals(cipher256, encrypted)
    }

    @Test
    fun testRandom() {
        val size = 256

        val key = ByteArray(size / 8)
        Random.nextBytes(key)
        val cipher = Rijndael256(key)

        for (i in 0..<1024) {
            val plain = ByteArray(size / 8)
            Random.nextBytes(plain)

            val encrypted = cipher.encrypt(plain)
            val decrypted = cipher.decrypt(encrypted)

            assertContentEquals(plain, decrypted)
        }
    }

    @Test
    fun testRijndael256PcfbKnownValues() {
        checkKnownPcfbValues(
            pcfb256EncryptKey,
            pcfb256EncryptIv,
            pcfb256EncryptPlaintext,
            pcfb256EncryptCiphertext
        )
        checkKnownPcfbValues(
            pcfb256DecryptKey,
            pcfb256DecryptIv,
            pcfb256DecryptPlaintext,
            pcfb256DecryptCiphertext
        )
    }

    @Test
    fun testRijndael256PcfbKnownValuesRandomLength() {
        checkKnownPcfbValuesRandomLength(
            pcfb256EncryptKey,
            pcfb256EncryptIv,
            pcfb256EncryptPlaintext,
            pcfb256EncryptCiphertext
        )
        checkKnownPcfbValuesRandomLength(
            pcfb256DecryptKey,
            pcfb256DecryptIv,
            pcfb256DecryptPlaintext,
            pcfb256DecryptCiphertext
        )
    }

    @Test
    fun testRandomPcfb() {
        for (i in 0..<1024) {
            val plaintext = ByteArray(Random.nextInt(0, 4096) + 1)
            val key = ByteArray(32)
            val iv = ByteArray(32)

            Random.nextBytes(plaintext)
            Random.nextBytes(key)
            Random.nextBytes(iv)

            // First encrypt as a block.
            val cipher = Rijndael256(key)
            cipher.resetCfb(iv)
            val ciphertext = cipher.encryptCfb(plaintext, 0, plaintext.size)

            // Now decrypt.
            cipher.resetCfb(iv)
            val finalPlaintext = cipher.decryptCfb(ciphertext, 0, ciphertext.size)

            assertContentEquals(plaintext, finalPlaintext)

            // Now encrypt again, in random pieces.
            cipher.resetCfb(iv)
            var output = ByteArray(0)
            var ptr = 0
            while (ptr < plaintext.size) {
                val max = plaintext.size - ptr
                val count = if (max == 1) 1 else Random.nextInt(0, max - 1) + 1
                output += cipher.encryptCfb(plaintext, ptr, count)
                ptr += count
            }
            assertContentEquals(ciphertext, output)

            // ... and decrypt again, in random pieces.
            cipher.resetCfb(iv)
            output = ByteArray(0)
            ptr = 0
            while (ptr < plaintext.size) {
                val max = plaintext.size - ptr
                val count = if (max == 1) 1 else Random.nextInt(0, max - 1) + 1
                output += cipher.decryptCfb(ciphertext, ptr, count)
                ptr += count
            }
            assertContentEquals(plaintext, output)
        }
    }

    private fun checkKnownPcfbValues(
        key: ByteArray,
        iv: ByteArray,
        plaintext: ByteArray,
        ciphertext: ByteArray
    ) {
        val cipher = Rijndael256(key)

        val encrypted = cipher.encryptCfb(plaintext, iv)
        assertContentEquals(ciphertext, encrypted)

        val decrypted = cipher.decryptCfb(ciphertext, iv)
        assertContentEquals(plaintext, decrypted)
    }

    private fun checkKnownPcfbValuesRandomLength(
        key: ByteArray, iv: ByteArray,
        plaintext: ByteArray,
        ciphertext: ByteArray
    ) {
        val cipher = Rijndael256(key)

        for (i in 0..<1024) {

            cipher.resetCfb(iv)
            var ptr = 0
            var output = ByteArray(0)
            while (ptr < plaintext.size) {
                val max = plaintext.size - ptr
                val count = if (max == 1) 1 else Random.nextInt(0, max - 1) + 1

                output += cipher.encryptCfb(plaintext, ptr, count)

                ptr += count
            }

            assertContentEquals(ciphertext, output)

            cipher.resetCfb(iv)
            ptr = 0
            output = ByteArray(0)
            while (ptr < plaintext.size) {
                val max = plaintext.size - ptr
                val count = if (max == 1) 1 else Random.nextInt(0, max - 1) + 1

                output += cipher.decryptCfb(ciphertext, ptr, count)
                ptr += count
            }

            assertContentEquals(plaintext, output)
        }
    }
}
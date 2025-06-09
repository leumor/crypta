package network.crypta.crypto

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES
import kotlin.experimental.xor

/** Implementation of [CryptoCipher] using AES-CTR with 256-bit keys. */
internal class AesCtrCipher(key: ByteArray) : CryptoCipher {
    @OptIn(DelicateCryptographyApi::class)
    private val ctr = run {
        val provider = CryptographyProvider.Default
        val aes = provider.get(AES.CTR)
        val aesKey = aes.keyDecoder().decodeFromByteArrayBlocking(AES.Key.Format.RAW, key)
        aesKey.cipher()
    }

    private val blockSize = 16
    private val zeroBlock = ByteArray(blockSize)

    override fun encrypt(iv: ByteArray, data: ByteArray): ByteArray = process(iv.copyOf(), data)

    override fun decrypt(iv: ByteArray, data: ByteArray): ByteArray = process(iv.copyOf(), data)

    override fun encryptor(iv: ByteArray): CryptoCipherStream = CtrStream(iv.copyOf())

    override fun decryptor(iv: ByteArray): CryptoCipherStream = CtrStream(iv.copyOf())

    private inner class CtrStream(private val counter: ByteArray) : CryptoCipherStream {
        private var keystream = ByteArray(0)
        private var pos = 0

        @OptIn(DelicateCryptographyApi::class)
        override fun update(data: ByteArray, offset: Int, length: Int): ByteArray {
            val out = ByteArray(length)
            var off = 0
            while (off < length) {
                if (pos == keystream.size) {
                    keystream = ctr.encryptWithIvBlocking(counter, zeroBlock)
                    increment(counter)
                    pos = 0
                }
                val block = minOf(keystream.size - pos, length - off)
                for (i in 0 until block) {
                    out[off + i] = data[offset + off + i] xor keystream[pos + i]
                }
                pos += block
                off += block
            }
            return out
        }
    }

    @OptIn(DelicateCryptographyApi::class)
    private fun process(counter: ByteArray, input: ByteArray): ByteArray {
        val out = ByteArray(input.size)
        var keystream = ByteArray(0)
        var ksPos = 0
        var pos = 0
        while (pos < input.size) {
            if (ksPos == keystream.size) {
                keystream = ctr.encryptWithIvBlocking(counter, zeroBlock)
                increment(counter)
                ksPos = 0
            }
            val block = minOf(keystream.size - ksPos, input.size - pos)
            for (i in 0 until block) {
                out[pos + i] = input[pos + i] xor keystream[ksPos + i]
            }
            ksPos += block
            pos += block
        }
        return out
    }

    private fun increment(counter: ByteArray) {
        for (i in counter.lastIndex downTo 0) {
            val v = (counter[i].toInt() + 1) and 0xFF
            counter[i] = v.toByte()
            if (v != 0) break
        }
    }
}

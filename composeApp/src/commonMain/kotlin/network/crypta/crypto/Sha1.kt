package network.crypta.crypto

object Sha1 {
    fun digest(data: ByteArray): ByteArray {
        val message = data.copyOf()
        val bitLen = message.size * 8L
        var padded = message + 0x80.toByte()
        while ((padded.size % 64) != 56) {
            padded += 0.toByte()
        }
        val lenBytes = ByteArray(8)
        for (i in 0..7) {
            lenBytes[7 - i] = ((bitLen ushr (8 * i)) and 0xff).toByte()
        }
        padded += lenBytes

        var h0 = 0x67452301
        var h1 = 0xEFCDAB89.toInt()
        var h2 = 0x98BADCFE.toInt()
        var h3 = 0x10325476
        var h4 = 0xC3D2E1F0.toInt()

        val w = IntArray(80)
        var i = 0
        while (i < padded.size) {
            for (j in 0 until 16) {
                val index = i + j * 4
                w[j] = (padded[index].toInt() and 0xff shl 24) or
                        (padded[index + 1].toInt() and 0xff shl 16) or
                        (padded[index + 2].toInt() and 0xff shl 8) or
                        (padded[index + 3].toInt() and 0xff)
            }
            for (j in 16 until 80) {
                val temp = w[j - 3] xor w[j - 8] xor w[j - 14] xor w[j - 16]
                w[j] = (temp shl 1) or (temp ushr 31)
            }
            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4
            for (j in 0 until 80) {
                val (f, k) = when (j) {
                    in 0..19 -> Pair((b and c) or (b.inv() and d), 0x5A827999)
                    in 20..39 -> Pair(b xor c xor d, 0x6ED9EBA1)
                    in 40..59 -> Pair((b and c) or (b and d) or (c and d), 0x8F1BBCDC.toInt())
                    else -> Pair(b xor c xor d, 0xCA62C1D6.toInt())
                }
                val temp = ((a shl 5) or (a ushr 27)) + f + e + k + w[j]
                e = d
                d = c
                c = (b shl 30) or (b ushr 2)
                b = a
                a = temp
            }
            h0 += a
            h1 += b
            h2 += c
            h3 += d
            h4 += e
            i += 64
        }
        val out = ByteArray(20)
        val hs = intArrayOf(h0, h1, h2, h3, h4)
        var pos = 0
        for (h in hs) {
            out[pos++] = (h shr 24).toByte()
            out[pos++] = (h shr 16).toByte()
            out[pos++] = (h shr 8).toByte()
            out[pos++] = h.toByte()
        }
        return out
    }
}

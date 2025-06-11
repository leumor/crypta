package network.crypta.crypto

import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DsaTest {
    private val p = BigInteger.parseString(
        "a8f9cd201e5e35d892f85f80e4db2599a5676a3b1d4f190330ed3256b26d0e80a0e49a8fffaaad2a24f472d2573241d4d6d6c7480c80b4c67bb4479c15ada7ea8424d2502fa01472e760241713dab025ae1b02e1703a1435f62ddf4ee4c1b664066eb22f2e3bf28bb70a2a76e4fd5ebe2d1229681b5b06439ac9c7e9d8bde283",
        16
    )
    private val q = BigInteger.parseString(
        "f85f0f83ac4df7ea0cdf8f469bfeeaea14156495",
        16
    )
    private val g = BigInteger.parseString(
        "2b3152ff6c62f14622b8f48e59f8af46883b38e79b8c74deeae9df131f8b856e3ad6c8455dab87cc0da8ac973417ce4f7878557d6cdf40b35b4a0ca3eb310c6a95d68ce284ad4e25ea28591611ee08b8444bd64b25f3f7c572410ddfb39cc728b9c936f85f419129869929cdb909a6a3a99bbe089216368171bd0ba81de4fe33",
        16
    )
    private val x = BigInteger.parseString(
        "c53eae6d45323164c7d07af5715703744a63fc3a",
        16
    )
    private val y = BigInteger.parseString(
        "313fd9ebca91574e1c2eebe1517c57e0c21b0209872140c5328761bbb2450b33f1b18b409ce9ab7c4cd8fda3391e8e34868357c199e16a6b2eba06d6749def791d79e95d3a4d09b24c392ad89dbf100995ae19c01062056bb14bce005e8731efde175f95b975089bdcdaea562b32786d96f5a31aedf75364008ad4fffebb970b",
        16
    )
    private val params = DsaParameters(p, q, g)
    private val dsa = Dsa(params)
    private val message = "hello".encodeToByteArray()
    private val k = BigInteger.fromInt(123456789).mod(q)
    private val expectedR = BigInteger.parseString("79402cc0e77cfe15824d4ed58397e6fa62f4a063", 16)
    private val expectedS = BigInteger.parseString("934e48e66c82270e9087cb976d1f6ffc2ee3b0ee", 16)

    @Test
    fun testSignVerify() {
        val (r, s) = dsa.sign(message, x, k)
        assertEquals(expectedR, r)
        assertEquals(expectedS, s)
        assertTrue(dsa.verify(message, y, r, s))
    }

    @Test
    fun testGenerateKeyPair() {
        val (pub, priv) = dsa.generateKeyPair()

        val x = priv.x
        val y = pub.y
        val msg = "hello".encodeToByteArray()
        val (r, s) = dsa.sign(msg, x)
        assertTrue(dsa.verify(msg, y, r, s))
    }

    @Test
    fun testKeyValidation() {
        assertFailsWith<IllegalArgumentException> { DsaPublicKey(BigInteger.ZERO, params) }
        assertFailsWith<IllegalArgumentException> { DsaPublicKey(params.p, params) }
        assertFailsWith<IllegalArgumentException> { DsaPrivateKey(BigInteger.ZERO, params) }
        assertFailsWith<IllegalArgumentException> { DsaPrivateKey(params.q, params) }
    }

    @Test
    fun testMpiRoundTrip() {
        val numbers = listOf(
            BigInteger.ZERO,
            BigInteger.ONE,
            BigInteger.fromInt(0x12345678),
            BigInteger.parseString("abcdef1234567890", 16),
        )
        for (n in numbers) {
            val bytes = n.toMPI()
            val (decoded, idx) = bytes.readMPI()
            assertEquals(bytes.size, idx)
            assertEquals(n, decoded)
        }
    }

    @Test
    fun testMpiKnownValues() {
        val cases = mapOf(
            BigInteger.fromInt(9) to "000409",
            BigInteger.parseString("1234567890123456789", 10) to "003d112210f47de98115",
            BigInteger.parseString(
                "100200300400500600700800900",
                10
            ) to "005752e23d2b3cc71d9f4a0f84",
        )
        for ((num, hex) in cases) {
            val bytes = num.toMPI()
            val actualHex = bytes
                .joinToString("") {
                    ((it.toInt() and 0xFF).toString(16)).padStart(2, '0')
                }
            assertEquals(hex, actualHex)
            val (decoded, _) = bytes.readMPI()
            assertEquals(num, decoded)
        }
    }
}

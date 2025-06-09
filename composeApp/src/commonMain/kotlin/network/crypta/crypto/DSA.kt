package network.crypta.crypto

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlin.random.Random

/**
 * Minimal implementation of the Digital Signature Algorithm (DSA) for Kotlin
 * Multiplatform.
 */
class DSA(
    val p: BigInteger,
    val q: BigInteger,
    val g: BigInteger
) {
    /**
     * Sign [message] using private exponent [x]. When [k] is provided the
     * signature will be deterministic. The function ensures that neither `r`
     * nor `s` are zero as required by the specification.
     */
    fun sign(
        message: ByteArray,
        x: BigInteger,
        k: BigInteger? = null,
    ): Pair<BigInteger, BigInteger> {
        var kVal = k ?: randomK()
        var r: BigInteger
        var s = BigInteger.ZERO
        val h = BigInteger.fromByteArray(Sha1.digest(message), Sign.POSITIVE)
        do {
            if (k == null) kVal = randomK()
            r = modPow(g, kVal, p).mod(q)
            if (r == BigInteger.ZERO) continue
            val kInv = kVal.modInverse(q)
            s = (kInv * (h + x * r)).mod(q)
        } while (s == BigInteger.ZERO)
        return r to s
    }

    /** Verify signature [r],[s] of [message] using public exponent [y]. */
    fun verify(message: ByteArray, y: BigInteger, r: BigInteger, s: BigInteger): Boolean {
        if (r <= BigInteger.ZERO || r >= q) return false
        if (s <= BigInteger.ZERO || s >= q) return false
        val h = BigInteger.fromByteArray(Sha1.digest(message), Sign.POSITIVE)
        val w = s.modInverse(q)
        val u1 = (h * w).mod(q)
        val u2 = (r * w).mod(q)
        val v = (modPow(g, u1, p) * modPow(y, u2, p)).mod(p).mod(q)
        return v == r.mod(q)
    }

    private fun randomK(): BigInteger {
        val bytes = ByteArray((q.bitLength() + 7) / 8)
        var k: BigInteger
        do {
            Random.nextBytes(bytes)
            k = BigInteger.fromByteArray(bytes, Sign.POSITIVE).mod(q)
        } while (k == BigInteger.ZERO)
        return k
    }

    companion object Companion {
        private fun modPow(base: BigInteger, exp: BigInteger, mod: BigInteger): BigInteger {
            var result = BigInteger.ONE
            var b = base.mod(mod)
            var e = exp
            while (e > BigInteger.ZERO) {
                if ((e and BigInteger.ONE) != BigInteger.ZERO) {
                    result = (result * b).mod(mod)
                }
                e = e shr 1
                b = (b * b).mod(mod)
            }
            return result
        }
    }
}

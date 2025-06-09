package network.crypta.crypto

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlin.random.Random

/**
 * A minimal implementation of the Digital Signature Algorithm (DSA) for Kotlin
 * Multiplatform.
 *
 * This class provides methods to sign data and verify digital signatures
 * according to the FIPS 186-4 standard. It relies on a set of domain
 * parameters (`p`, `q`, `g`) which must be provided upon instantiation.
 * The message is hashed using SHA-1 before signing or verification.
 *
 * @property p The prime modulus, a large prime number.
 * @property q The prime divisor, a prime factor of `p-1`.
 * @property g The generator, calculated as `h^((p-1)/q) mod p` for some `h`.
 * @constructor Creates a DSA instance with the given domain parameters.
 */
class DSA(
    val p: BigInteger,
    val q: BigInteger,
    val g: BigInteger
) {
    /**
     * Creates a digital signature for a given message.
     *
     * This function takes a message and a private key `x` to produce a
     * signature pair (`r`, `s`). The message is first hashed using SHA-1.
     *
     * A per-message secret number `k` is used in the signing process. If `k` is
     * not provided, a cryptographically secure random value is generated internally.
     * Providing a value for `k` makes the signature deterministic, which can be
     * useful for testing or specific protocols like RFC 6979, but it is **critical**
     * that `k` is never reused with the same private key `x`.
     *
     * The implementation ensures that neither `r` nor `s` is zero, as required
     * by the DSA standard. If a generated value is zero, the process is repeated
     * with a new `k`.
     *
     * @param message The raw data to be signed. It will be hashed using SHA-1.
     * @param x The private key, a randomly selected integer in the range `[1, q-1]`.
     * @param k An optional per-message secret number in the range `[1, q-1]`.
     *          If `null`, a random one will be generated.
     * @return A [Pair] containing the two components of the signature, `r` and `s`.
     */
    fun sign(
        message: ByteArray,
        x: BigInteger,
        k: BigInteger? = null,
    ): Pair<BigInteger, BigInteger> {
        var kVal = k ?: randomK()
        var r: BigInteger
        var s = BigInteger.ZERO
        // h = H(m), where H is the hash function (SHA-1).
        val h = BigInteger.fromByteArray(Sha1.digest(message), Sign.POSITIVE)

        // Per FIPS 186-4, Section 4.6, step 5: In the unlikely event that r=0 or s=0,
        // a new value of k must be generated and the signature recomputed.
        do {
            // If the initial k was user-provided and resulted in a zero r or s,
            // we must switch to a random k. However, this implementation re-uses
            // a new random k on each loop iteration if the initial k was null.
            if (k == null) kVal = randomK()

            // r = (g^k mod p) mod q
            r = modPow(g, kVal, p).mod(q)
            if (r == BigInteger.ZERO) continue

            // s = (k^-1 * (H(m) + x*r)) mod q
            val kInv = kVal.modInverse(q)
            s = (kInv * (h + x * r)).mod(q)
        } while (s == BigInteger.ZERO)
        return r to s
    }

    /**
     * Verifies a digital signature against a message and a public key.
     *
     * This function checks if the provided signature (`r`, `s`) is valid for the
     * given `message` and public key `y`. The message is first hashed using SHA-1
     * to perform the verification.
     *
     * The verification process involves several steps, including checking that `r` and `s`
     * are in the valid range `(0, q)`, and then performing the core DSA
     * mathematical verification.
     *
     * @param message The original raw data that was signed.
     * @param y The public key corresponding to the private key used for signing.
     *          The public key is calculated as `g^x mod p`.
     * @param r The first component of the signature.
     * @param s The second component of the signature.
     * @return `true` if the signature is valid, `false` otherwise.
     */
    fun verify(message: ByteArray, y: BigInteger, r: BigInteger, s: BigInteger): Boolean {
        // Per FIPS 186-4, Section 4.7, step 1: Verify that 0 < r < q and 0 < s < q.
        if (r <= BigInteger.ZERO || r >= q) return false
        if (s <= BigInteger.ZERO || s >= q) return false

        // h = H(m), where H is the hash function (SHA-1).
        val h = BigInteger.fromByteArray(Sha1.digest(message), Sign.POSITIVE)

        // w = s'^-1 mod q
        val w = s.modInverse(q)

        // u1 = (H(m) * w) mod q
        val u1 = (h * w).mod(q)
        // u2 = (r' * w) mod q
        val u2 = (r * w).mod(q)

        // v = ((g^u1 * y^u2) mod p) mod q
        val v = (modPow(g, u1, p) * modPow(y, u2, p)).mod(p).mod(q)

        // The signature is valid if v == r'.
        return v == r.mod(q)
    }

    /**
     * Generates a cryptographically secure random integer `k` for the signing process.
     *
     * The integer `k` must be a per-message secret and must be in the range `[1, q-1]`.
     * This function ensures that the generated number is not zero.
     *
     * @return A secure random [BigInteger] `k` such that `1 <= k < q`.
     */
    private fun randomK(): BigInteger {
        val bytes = ByteArray((q.bitLength() + 7) / 8)
        var k: BigInteger
        do {
            Random.nextBytes(bytes)
            k = BigInteger.fromByteArray(bytes, Sign.POSITIVE).mod(q)
        } while (k == BigInteger.ZERO)
        return k
    }

    /**
     * Companion object for helper functions.
     */
    companion object Companion {
        /**
         * Performs modular exponentiation.
         *
         * This function efficiently calculates `(base ^ exp) mod mod`. It is a fundamental
         * operation in many public-key cryptography algorithms, including DSA.
         * This implementation uses the right-to-left binary method (also known as
         * square-and-multiply).
         *
         * @param base The base of the exponentiation.
         * @param exp The exponent.
         * @param mod The modulus.
         * @return The result of `(base ^ exp) mod mod`.
         */
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

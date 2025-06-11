package network.crypta.crypto

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlin.random.Random

/**
 * Parameters for the DSA algorithm consisting of the prime modulus `p`,
 * the prime divisor `q` and the generator `g`.
 */
data class DsaParameters(
    val p: BigInteger,
    val q: BigInteger,
    val g: BigInteger,
) {
    init {
        require(p > BigInteger.ZERO && q > BigInteger.ZERO && g > BigInteger.ZERO)
    }

    /** Encodes the parameters as a concatenation of MPI-encoded values. */
    fun toByteArray(): ByteArray = p.toMPI() + q.toMPI() + g.toMPI()

    companion object {
        val DEFAULT = DsaParameters(
            p = BigInteger.parseString(
                "008608ac4f55361337f2a3e38ab1864ff3c98d66411d8d2afc9c526320c541f65078e86bc78494a5d73e4a9a67583f941f2993ed6c97dbc795dd88f0915c9cfbffc7e5373cde13e3c7ca9073b9106eb31bf82272ed0057f984a870a19f8a83bfa707d16440c382e62d3890473ea79e9d50c4ac6b1f1d30b10c32a02f685833c6278fc29eb3439c5333885614a115219b3808c92a37a0f365cd5e61b5861761dad9eff0ce23250f558848f8db932b87a3bd8d7a2f7cf99c75822bdc2fb7c1a1d78d0bcf81488ae0de5269ff853ab8b8f1f2bf3e6c0564573f612808f68dbfef49d5c9b4a705794cf7a424cd4eb1e0260552e67bfc1fa37b4a1f78b757ef185e86e9",
                16
            ),
            q = BigInteger.parseString(
                "00b143368abcd51f58d6440d5417399339a4d15bef096a2c5d8e6df44f52d6d379",
                16
            ),
            g = BigInteger.parseString(
                "51a45ab670c1c9fd10bd395a6805d33339f5675e4b0d35defc9fa03aa5c2bf4ce9cfcdc256781291bfff6d546e67d47ae4e160f804ca72ec3c5492709f5f80f69e6346dd8d3e3d8433b6eeef63bce7f98574185c6aff161c9b536d76f873137365a4246cf414bfe8049ee11e31373cd0a6558e2950ef095320ce86218f992551cc292224114f3b60146d22dd51f8125c9da0c028126ffa85efd4f4bfea2c104453329cc1268a97e9a835c14e4a9a43c6a1886580e35ad8f1de230e1af32208ef9337f1924702a4514e95dc16f30f0c11e714a112ee84a9d8d6c9bc9e74e336560bb5cd4e91eabf6dad26bf0ca04807f8c31a2fc18ea7d45baab7cc997b53c356",
                16
            )
        )
        /**
         * Decodes parameters from a byte array starting at [offset].
         *
         * @return The decoded [DsaParameters] and the index after the consumed bytes.
         */
        fun fromByteArray(bytes: ByteArray, offset: Int = 0): Pair<DsaParameters, Int> {
            var idx = offset
            val (p, i1) = bytes.readMPI(idx)
            idx = i1
            val (q, i2) = bytes.readMPI(idx)
            idx = i2
            val (g, i3) = bytes.readMPI(idx)
            idx = i3
            return DsaParameters(p, q, g) to idx
        }
    }
}

/** A DSA public key, storing the value `y` and its associated [DsaParameters]. */
data class DsaPublicKey(
    val y: BigInteger,
    val parameters: DsaParameters = DsaParameters.DEFAULT,
) : CryptoKey {
    init {
        require(y > BigInteger.ZERO && y < parameters.p)
    }

    override val bytes: ByteArray = parameters.toByteArray() + y.toMPI()

    companion object {
        /** Constructs a key from its MPI-encoded byte representation. */
        fun fromByteArray(bytes: ByteArray): DsaPublicKey {
            val (params, idx) = DsaParameters.fromByteArray(bytes, 0)
            val (y, _) = bytes.readMPI(idx)
            return DsaPublicKey(y, params)
        }

        /**
         * Derives a [DsaPublicKey] from the provided [DsaPrivateKey].
         *
         * This uses the formula `y = g^x mod p` where `x` is the private key and
         * `g`, `p` are taken from the private key's parameters.
         */
        fun fromPrivateKey(
            privateKey: DsaPrivateKey,
            parameters: DsaParameters = DsaParameters.DEFAULT,
        ): DsaPublicKey {
            val y = Dsa.modPow(parameters.g, privateKey.x, parameters.p)
            return DsaPublicKey(y, parameters)
        }
    }
}

/** A DSA private key storing the secret value `x`. */
class DsaPrivateKey(
    val x: BigInteger,
    parameters: DsaParameters = DsaParameters.DEFAULT,
) : CryptoKey {
    init {
        require(x > BigInteger.ZERO && x < parameters.q)
    }

    override val bytes: ByteArray = x.toMPI()

    companion object {
        /** Constructs a private key from MPI-encoded bytes. */
        fun fromByteArray(bytes: ByteArray, parameters: DsaParameters): DsaPrivateKey {
            val (x, _) = bytes.readMPI()
            return DsaPrivateKey(x, parameters)
        }
    }
}


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
class Dsa(
    val parameters: DsaParameters = DsaParameters.DEFAULT
) {
    val p: BigInteger = parameters.p
    val q: BigInteger = parameters.q
    val g: BigInteger = parameters.g
    /**
     * Generates a new DSA key pair.
     *
     * The private key `x` is a random integer in the range `[1, q-1]`.
     * The public key `y` is calculated as `g^x mod p`.
     *
     * @return A [Pair] containing the new [DsaPublicKey] and [DsaPrivateKey].
     */
    fun generateKeyPair(): Pair<DsaPublicKey, DsaPrivateKey> {
        val x = randomK()
        val y = modPow(g, x, p)
        val pub = DsaPublicKey(y, parameters)
        val priv = DsaPrivateKey(x, parameters)
        return pub to priv
    }

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
        // h = H(m), where H is the chosen hash function (SHA-1).
        val h = BigInteger.fromByteArray(
            Hash.digest(HashAlgorithm.SHA1, message),
            Sign.POSITIVE
        )

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

        // h = H(m), where H is the chosen hash function (SHA-1).
        val h = BigInteger.fromByteArray(
            Hash.digest(HashAlgorithm.SHA1, message),
            Sign.POSITIVE
        )

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
        internal fun modPow(base: BigInteger, exp: BigInteger, mod: BigInteger): BigInteger {
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

/** Encodes this [BigInteger] using the MPI format employed by Freenet. */
internal fun BigInteger.toMPI(): ByteArray {
    val bitLength = this.bitLength()
    val byteLength = (bitLength + 7) / 8
    val raw = this.toByteArray()
    val unsigned = if (raw.isNotEmpty() && raw.first() == 0.toByte()) {
        raw.copyOfRange(1, raw.size)
    } else {
        raw
    }
    val out = ByteArray(2 + byteLength)
    out[0] = (bitLength shr 8).toByte()
    out[1] = bitLength.toByte()
    unsigned.copyInto(out, destinationOffset = out.size - unsigned.size)
    return out
}

/** Reads an MPI-encoded [BigInteger] starting at [offset]. */
internal fun ByteArray.readMPI(offset: Int = 0): Pair<BigInteger, Int> {
    val b1 = this[offset].toInt() and 0xFF
    val b2 = this[offset + 1].toInt() and 0xFF
    val bitLength = (b1 shl 8) + b2
    val byteLength = (bitLength + 7) / 8
    val data = this.copyOfRange(offset + 2, offset + 2 + byteLength)
    val value = BigInteger.fromByteArray(data, Sign.POSITIVE)
    return value to (offset + 2 + byteLength)
}

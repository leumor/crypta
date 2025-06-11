package network.crypta.crypto

import network.crypta.util.decodeFreenetBase64
import network.crypta.util.encodeFreenetBase64

/**
 * A base interface for cryptographic keys.
 *
 * This serves as a common abstraction for various key types, providing a standardized
 * way to access their raw byte representation.
 */
interface CryptoKey {
    /** The raw byte data of the cryptographic key. */
    val bytes: ByteArray
}

/**
 * Encodes the raw bytes of this [CryptoKey] into a Freenet-style Base64 string.
 *
 * @return The Base64 encoded string representation of the key.
 */
fun CryptoKey.toBase64(): String = bytes.encodeFreenetBase64()

/**
 * Decodes a Freenet-style Base64 string into a [CryptoKey] of type [T].
 *
 * @param T The specific [CryptoKey] type to be created (e.g., [SecretKey], [DsaPublicKey]).
 * @param factory A lambda function that constructs an instance of [T] from a [ByteArray].
 * @return An instance of [T] created from the decoded Base64 string.
 */
fun <T : CryptoKey> String.fromBase64(factory: (ByteArray) -> T): T =
    factory(this.decodeFreenetBase64())

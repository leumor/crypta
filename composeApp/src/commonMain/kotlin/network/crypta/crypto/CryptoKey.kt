package network.crypta.crypto

import network.crypta.util.decodeFreenetBase64
import network.crypta.util.encodeFreenetBase64

/** Base interface for simple key wrappers that expose their raw bytes. */
interface CryptoKey {
    val bytes: ByteArray
}

/** Encodes this key using Freenet-style Base64. */
fun CryptoKey.toBase64(): String = bytes.encodeFreenetBase64()

/** Decodes a Freenet-style Base64 string into a key using [factory]. */
fun <T : CryptoKey> String.fromBase64(factory: (ByteArray) -> T): T =
    factory(this.decodeFreenetBase64())

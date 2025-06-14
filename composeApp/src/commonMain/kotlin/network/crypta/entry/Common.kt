package network.crypta.entry

import network.crypta.crypto.CryptoKey
import network.crypta.crypto.SecretKey
import kotlin.jvm.JvmInline

/** Number of bytes in a routing key. */
const val ROUTING_KEY_SIZE = 32

/**
 * Defines the types of Crypta keys, used to identify different kinds of URIs.
 */
enum class KeyType {
    /** Updatable Subspace Key: for content that can be updated, like websites. */
    USK,

    /** Keyword Signed Key: a user-friendly key derived from a simple text string. */
    KSK,

    /** Signed Subspace Key: uses a public/private key pair to ensure only the owner can update content. */
    SSK,

    /** Content Hash Key: a key derived from the hash of the content itself, for static data. */
    CHK,
}

/**
 * A wrapper for the byte array that constitutes a routing key.
 * The routing key is a 32-byte hash used to locate data on the Crypta network.
 *
 * @property bytes The raw byte array of the routing key.
 * @constructor Ensures the routing key is exactly [ROUTING_KEY_SIZE] bytes long.
 */
@JvmInline
value class RoutingKey(override val bytes: ByteArray) : CryptoKey {
    init {
        require(bytes.size == ROUTING_KEY_SIZE) { "Routing key must be $ROUTING_KEY_SIZE bytes" }
    }
}

/**
 * A type alias for a [SecretKey] used for decrypting content.
 * This key is known only to the client and is part of the full URI, but not stored by Crypta nodes.
 */
typealias SharedKey = SecretKey

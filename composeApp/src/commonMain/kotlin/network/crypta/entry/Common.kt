package network.crypta.entry

import network.crypta.crypto.CryptoKey
import network.crypta.crypto.SecretKey
import kotlin.jvm.JvmInline

/** Number of bytes in a routing key. */
const val ROUTING_KEY_SIZE = 32

/** Types of Crypta URIs. */
enum class KeyType { USK, KSK, SSK, CHK }

@JvmInline
value class RoutingKey(override val bytes: ByteArray) : CryptoKey {
    init {
        require(bytes.size == ROUTING_KEY_SIZE) { "Routing key must be $ROUTING_KEY_SIZE bytes" }
    }
}

typealias SharedKey = SecretKey

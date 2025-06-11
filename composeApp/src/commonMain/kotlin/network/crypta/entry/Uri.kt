package network.crypta.entry

import network.crypta.entry.RoutingKey
import network.crypta.entry.SharedKey
import network.crypta.crypto.fromBase64
import network.crypta.crypto.toBase64
import network.crypta.crypto.SecretKey
import network.crypta.util.decodeFreenetBase64
import network.crypta.util.encodeFreenetBase64
import network.crypta.util.urlDecode
import network.crypta.util.urlEncode
import network.crypta.util.URLEncodedFormatException

/** Exception thrown when parsing a URI fails. */
class MalformedUriException(message: String) : Exception(message)

private val URI_PREFIX =
    Regex("^(https?://[^/]+/+)?(((ext|web)\\+)?(freenet|hyphanet|hypha):)?")
private const val URI_SEPARATOR = '/'

/**
 * Representation of a Crypta URI.
 */
class Uri {
    val uriType: KeyType
    val metaStrings: List<String>
    val keys: Keys

    @Throws(MalformedUriException::class)
    constructor(uri: String, noTrim: Boolean = false) {
        var tmp = if (noTrim) uri else uri.trim()

        val qIndex = tmp.indexOf('?')
        if (qIndex >= 0) tmp = tmp.substring(0, qIndex)

        if (tmp.indexOf('@') < 0 || tmp.indexOf(URI_SEPARATOR) < 0) {
            try {
                tmp = urlDecode(tmp, false)
            } catch (_: URLEncodedFormatException) {
                throw MalformedUriException(
                    "Invalid URI: no @ or /, or @ or / is escaped but there are invalid escapes"
                )
            }
        }

        tmp = URI_PREFIX.replace(tmp, "")

        var at = tmp.indexOf('@')
        if (at == -1) throw MalformedUriException("There is no @ in that URI! ($tmp)")

        val typeStr = tmp.substring(0, at).uppercase()
        tmp = tmp.substring(at + 1)

        uriType = try {
            KeyType.valueOf(typeStr)
        } catch (_: IllegalArgumentException) {
            throw MalformedUriException("Invalid key type: $typeStr")
        }

        at = tmp.indexOf(URI_SEPARATOR)
        val path: String
        if (at == -1) {
            keys = Keys(null, null, emptyList())
            path = tmp
        } else {
            val keysStr = tmp.substring(0, at)
            keys = parseKeysStr(keysStr)
            path = tmp.substring(at)
        }

        metaStrings = parseMetaStrings(path)
    }

    constructor(
        uriType: KeyType,
        routingKey: RoutingKey?,
        sharedKey: SharedKey?,
        extra: ByteArray,
        metaStrings: List<String>
    ) : this(uriType, Keys(routingKey, sharedKey, extra), metaStrings)

    constructor(uriType: KeyType, keys: Keys, metaStrings: List<String>) {
        this.uriType = uriType
        this.keys = keys
        this.metaStrings = ArrayList(metaStrings)
    }



    data class Keys(
        val routingKey: RoutingKey?,
        val sharedKey: SharedKey?,
        val extra: List<Byte>
    ) {
        constructor(
            routingKey: RoutingKey?,
            sharedKey: SharedKey?,
            extra: ByteArray?
        ) : this(routingKey, sharedKey, extra?.toList() ?: emptyList())

        fun getExtraBytes(): ByteArray = extra.toByteArray()
    }

    override fun toString(): String = toLongString(prefix = false, pureAscii = false)

    fun toLongString(prefix: Boolean = false, pureAscii: Boolean = false): String {
        val sb = StringBuilder()
        if (prefix) sb.append("freenet:")
        sb.append(uriType.name).append('@')
        var hasKeys = false
        keys.routingKey?.let {
            sb.append(it.toBase64())
            hasKeys = true
        }
        keys.sharedKey?.let {
            sb.append(',').append(it.toBase64())
        }
        if (keys.extra.isNotEmpty()) {
            sb.append(',').append(keys.getExtraBytes().encodeFreenetBase64())
        }
        val metaSb = StringBuilder()
        for (m in metaStrings) {
            metaSb.append(URI_SEPARATOR)
                .append(urlEncode(m, URI_SEPARATOR.toString(), pureAscii))
        }
        if (!hasKeys && metaSb.isNotEmpty()) {
            metaSb.deleteCharAt(0)
        }
        sb.append(metaSb)
        return sb.toString()
    }

    override fun equals(other: Any?): Boolean {
        val o = other as? Uri ?: return false
        return uriType == o.uriType && metaStrings == o.metaStrings && keys == o.keys
    }

    override fun hashCode(): Int = uriType.hashCode() * 31 + metaStrings.hashCode() * 31 + keys.hashCode()

    @Throws(MalformedUriException::class)
    private fun parseKeysStr(keysStr: String): Keys {
        var routingKey = ""
        var cryptoKey = ""
        var extra = ""
        var comma = keysStr.indexOf(',')
        if (comma >= 0) {
            routingKey = keysStr.substring(0, comma)
            var remainder = keysStr.substring(comma + 1)
            comma = remainder.indexOf(',')
            if (comma >= 0) {
                cryptoKey = remainder.substring(0, comma)
                remainder = remainder.substring(comma + 1)
                if (remainder.isNotEmpty()) extra = remainder
            }
        }
        return if (routingKey.isNotEmpty() && cryptoKey.isNotEmpty() && extra.isNotEmpty()) {
            try {
                Keys(
                    routingKey.fromBase64(::RoutingKey),
                    cryptoKey.fromBase64(::SecretKey),
                    extra.decodeFreenetBase64().toList()
                )
            } catch (_: Throwable) {
                throw MalformedUriException("Invalid URI: invalid routing key, crypto key or extra data")
            }
        } else {
            Keys(null, null, emptyList())
        }
    }

    private fun parseMetaStrings(uriPath: String): List<String> {
        if (uriPath.isEmpty()) return emptyList()
        val result = mutableListOf<String>()
        var start = 0
        while (true) {
            while (start < uriPath.length && uriPath[start] == URI_SEPARATOR) start++
            if (start > 1 && start < uriPath.length &&
                uriPath[start - 1] == URI_SEPARATOR && uriPath[start - 2] == URI_SEPARATOR
            ) {
                result.add("")
            }
            val end = uriPath.indexOf(URI_SEPARATOR, start)
            if (end != -1) {
                result.add(uriPath.substring(start, end))
                start = end + 1
            } else {
                if (start < uriPath.length) result.add(uriPath.substring(start))
                break
            }
        }
        return result
    }
}

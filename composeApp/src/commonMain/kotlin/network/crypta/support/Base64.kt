@file:OptIn(ExperimentalEncodingApi::class)

package network.crypta.support

import kotlin.io.encoding.Base64 as KotlinBase64
import kotlin.io.encoding.ExperimentalEncodingApi

/** Utility object offering simple Base64 encoding/decoding helpers. */
object Base64 {
    fun encode(input: ByteArray): String = KotlinBase64.Default.encode(input)

    fun decode(input: String): ByteArray = KotlinBase64.Default.decode(input)

    fun encodeUTF8(str: String): String = encode(str.encodeToByteArray())

    fun decodeUTF8(str: String): String = decode(str).decodeToString()

    fun encodeFreenet(input: ByteArray, padded: Boolean = false): String {
        val standardEncoded = KotlinBase64.Default.encode(input)
        val freenet = standardEncoded
            .replace('+', '~')
            .replace('/', '_')
        return if (padded) freenet else freenet.trimEnd('=')
    }

    fun decodeFreenet(str: String): ByteArray {
        val normalized = str
            .replace('~', '+')
            .replace('_', '/')

        val padded = when (normalized.length % 4) {
            2 -> "$normalized=="
            3 -> "$normalized="
            else -> normalized
        }

        return KotlinBase64.Default.decode(padded)
    }
}

/** Convenience extension for [Base64.encode]. */
fun ByteArray.encodeBase64(): String = Base64.encode(this)

/** Convenience extension for [Base64.decode]. */
fun String.decodeBase64(): ByteArray = Base64.decode(this)

/** Convenience extension for [Base64.encodeUTF8]. */
fun String.encodeUTF8Base64(): String = Base64.encodeUTF8(this)

/** Convenience extension for [Base64.decodeUTF8]. */
fun String.decodeUTF8Base64(): String = Base64.decodeUTF8(this)

/**
 * Encodes a [ByteArray] into a Crypta-compatible Base64 string.
 *
 * Crypta uses a URL-safe variant of Base64 where `+` becomes `~` and `/` becomes
 * `_`. Padding characters are optional and omitted by default.
 *
 * @param padded if `true`, the returned string includes `=` padding
 */
fun ByteArray.encodeFreenetBase64(padded: Boolean = false): String =
    Base64.encodeFreenet(this, padded)

/**
 * Decodes a Crypta-style Base64 string previously produced by
 * [encodeFreenetBase64]. Missing padding characters are tolerated.
 */
fun String.decodeFreenetBase64(): ByteArray = Base64.decodeFreenet(this)

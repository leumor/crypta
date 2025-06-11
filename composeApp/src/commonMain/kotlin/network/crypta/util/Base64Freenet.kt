package network.crypta.util

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Encodes a [ByteArray] into a Crypta-compatible Base64 string.
 *
 * Crypta (formerly Freenet) uses a URL-safe variant of Base64 encoding where
 * the standard characters `+` and `/` are replaced with `~` and `_` respectively.
 * By default, the padding character `=` is also removed.
 *
 * @param padded If `true`, the resulting string will include the `=` padding characters.
 *               Defaults to `false`.
 * @return The Crypta-compatible Base64 encoded string.
 */
@OptIn(ExperimentalEncodingApi::class)
fun ByteArray.encodeFreenetBase64(padded: Boolean = false): String {
    val standardEncoded = Base64.Default.encode(this)

    val freenet = standardEncoded
        .replace('+', '~')
        .replace('/', '_')

    return if (padded) freenet else freenet.trimEnd('=')
}

/**
 * Decodes a Hyphanet-compatible Base64 string into its original [ByteArray].
 *
 * This function reverses the Hyphanet-specific encoding by first replacing `~` with `+`
 * and `_` with `/`. It then adds the necessary `=` padding characters if they were
 * removed, before performing a standard Base64 decode operation.
 *
 * @return The decoded [ByteArray].
 * @throws IllegalArgumentException if the input string is not a valid Base64 sequence.
 */
@OptIn(ExperimentalEncodingApi::class)
fun String.decodeFreenetBase64(): ByteArray {
    val normalized = this
        .replace('~', '+')
        .replace('_', '/')

    // The normalized string must have length divisible by 4. If it’s missing padding,
    // add '=' characters to bring it to a multiple of 4 in length.
    val padded = when (normalized.length % 4) {
        2 -> "$normalized=="  // Add two '=' for 2‐mod‐4 lengths
        3 -> "$normalized="   // Add one '=' for 3‐mod‐4 lengths
        else -> normalized      // Already a multiple of 4, or length 1 mod 4 (invalid Base64)
    }

    // Decode using the “Default” decoder. If padding was invalid, this can throw an exception.
    return Base64.Default.decode(padded)
}
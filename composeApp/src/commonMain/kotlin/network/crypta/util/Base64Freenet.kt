package network.crypta.util

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
fun ByteArray.encodeFreenetBase64(): String {
    val standardEncoded = Base64.Default.encode(this)

    return standardEncoded
        .replace('+', '~')
        .replace('/', '_')
}

@OptIn(ExperimentalEncodingApi::class)
fun String.decodeFreenetBase64(): ByteArray {0
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
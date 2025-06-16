package network.crypta.support

/**
 * Utility functions for percent encoding and decoding URIs.
 *
 * The implementations here are based on the Freenet `URLEncoder` and
 * `URLDecoder` helpers but avoid any dependency on JVM-only APIs so they can be
 * used from Kotlin multiplatform common code.
 */

/**
 * Exception thrown when URL decoding fails.
 *
 * This typically occurs when a '%' character is not followed by two valid hexadecimal digits,
 * or when a disallowed sequence like `%00` is encountered.
 *
 * @param message A detailed message explaining the reason for the failure.
 */
class URLEncodedFormatException(message: String) : Exception(message)

/**
 * Decodes a percent-encoded string, assuming UTF-8 character encoding.
 *
 * This method decodes sequences of the form `%xy`, where `xy` are two hexadecimal digits.
 * It specifically disallows the `%00` sequence, throwing an exception if it is found.
 *
 * @param s The percent-encoded [String] to decode.
 * @param tolerant If `true`, the method attempts to be tolerant of malformed sequences
 *   at the beginning of the string. If an invalid escape (e.g., `"%_z"`) is found
 *   *before* any valid escape has been successfully decoded, it will be treated as a
 *   literal string. After the first successful decoding, any subsequent malformed
 *   escapes will cause a [URLEncodedFormatException] to be thrown, regardless of this flag.
 *   If `false`, any malformed escape will immediately throw an exception.
 * @return The decoded [String].
 * @throws URLEncodedFormatException if the input string contains an incomplete escape
 *   sequence (e.g., a trailing '%'), a disallowed sequence like `%00`, or a malformed
 *   escape when not in tolerant mode.
 */
fun urlDecode(s: String, tolerant: Boolean): String {
    if (s.isEmpty()) return ""
    val bytes = mutableListOf<Byte>()
    var i = 0
    var hasDecodedSomething = false
    while (i < s.length) {
        val c = s[i]
        if (c == '%') {
            if (i >= s.length - 2) throw URLEncodedFormatException(s)
            val hexVal = "" + s[i + 1] + s[i + 2]
            i += 2
            try {
                val read = DataUtil.hexToLong(hexVal)
                if (read == 0L) throw URLEncodedFormatException("Can't encode 00")
                bytes.add(read.toInt().toByte())
                hasDecodedSomething = true
            } catch (_: NumberFormatException) {
                if (tolerant && !hasDecodedSomething) {
                    ("%$hexVal").encodeToByteArray().forEach { bytes.add(it) }
                    i++
                    continue
                }
                throw URLEncodedFormatException("Not a two character hex % escape: $hexVal in $s")
            }
        } else {
            c.toString().encodeToByteArray().forEach { bytes.add(it) }
        }
        i++
    }
    return bytes.toByteArray().decodeToString()
}

/**
 * A string containing characters that are considered safe and will not be
 * percent-encoded by default. This set includes alphanumeric characters and `*`, `-`, `_`, `.`, `/`.
 * Note that this is a custom set and differs from the "unreserved" characters in RFC 3986 (which includes `~`).
 */
const val SAFE_URL_CHARACTERS =
    "*-_./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"

/**
 * Returns the string of characters that are considered safe for URLs and are not encoded.
 *
 * @return The string of safe characters.
 * @see SAFE_URL_CHARACTERS
 */
fun getSafeURLCharacters(): String = SAFE_URL_CHARACTERS

/**
 * Encodes a string for use in a URI.
 *
 * This is a convenience overload for [urlEncode] with no forced characters.
 *
 * @param url The [String] to encode.
 * @param ascii If `true`, all non-ASCII characters will be encoded. If `false`,
 *   certain printable, non-control, non-whitespace characters above U+007F may be
 *   left unencoded.
 * @return The percent-encoded [String].
 */
fun urlEncode(url: String, ascii: Boolean): String = urlEncode(url, null, ascii)

/**
 * Encodes a string for use in a URI, with options to force encoding for specific characters.
 *
 * A character is percent-encoded if it is not in [SAFE_URL_CHARACTERS], or if it is
 * present in the [force] string. The behavior for non-ASCII characters is controlled
 * by the [ascii] flag.
 *
 * @param url The [String] to encode.
 * @param force An optional [String] containing characters that should be forcibly
 *   encoded, even if they are otherwise considered safe.
 * @param ascii If `true`, all non-ASCII characters (code point >= 128) will be encoded.
 *   If `false`, printable, non-control, non-whitespace characters above U+007F may be
 *   left unencoded, provided they are not in the [force] string.
 * @return The percent-encoded [String].
 */
fun urlEncode(url: String, force: String?, ascii: Boolean): String {
    val enc = StringBuilder(url.length)
    for (c in url) {
        if ((SAFE_URL_CHARACTERS.indexOf(c) >= 0 ||
                    (!ascii && c.code >= 128 && c.isDefined() && !c.isISOControl() && !c.isWhitespace())) &&
            (force == null || force.indexOf(c) < 0)
        ) {
            enc.append(c)
        } else {
            for (b in c.toString().encodeToByteArray()) {
                val x = b.toInt() and 0xFF
                enc.append('%')
                if (x < 16) enc.append('0')
                enc.append(x.toString(16))
            }
        }
    }
    return enc.toString()
}

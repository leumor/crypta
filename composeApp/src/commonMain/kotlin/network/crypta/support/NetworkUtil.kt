package network.crypta.support

/**
 * Collection of helpers for working with network related strings such as
 * hostnames and textual IP address literals. These functions are implemented
 * without relying on platform specific networking APIs so that they can run on
 * all Kotlin targets.
 */
object NetworkUtil {
    // Regex derived from the original Freenet HostnameUtil implementation.
    // It allows hostnames containing letters, digits and a selection of
    // punctuation characters. A valid hostname must contain at least one dot
    // separating the domain labels and end with a top level domain of length
    // 2 to 6 characters.
    private val HOSTNAME_REGEX =
        Regex("(?:[-!#\\$%&'\\*+\\/0-9=?A-Z^_`a-z{|}]+\\.)+[a-zA-Z]{2,6}")

    /**
     * Returns `true` if [hn] represents a syntactically valid hostname.
     *
     * When [allowIPAddress] is `true`, IPv4 and IPv6 literals are also accepted
     * as valid hostnames.
     */
    fun isValidHostname(hn: String, allowIPAddress: Boolean): Boolean {
        if (allowIPAddress && isIpAddress(hn)) return true
        return HOSTNAME_REGEX.matches(hn)
    }

    /** Returns true if the given [address] string is in a site local range. */
    fun isSiteLocalAddress(address: String): Boolean {
        val bytes = parseAddress(address) ?: return false
        return isSiteLocalAddress(bytes)
    }

    /**
     * Returns true if [address] represents a valid public address.
     * @param address the textual representation of the address
     * @param includeLocalAddressesInNoderefs whether site-local, link-local and
     * loopback addresses should be considered valid
     */
    fun isValidAddress(address: String, includeLocalAddressesInNoderefs: Boolean): Boolean {
        val bytes = parseAddress(address) ?: return false
        return isValidAddress(bytes, includeLocalAddressesInNoderefs)
    }

    // ---------------- private helpers ----------------

    private fun isIpAddress(addr: String): Boolean = isIPv4(addr) || isIPv6(addr)

    private fun isIPv4(address: String): Boolean = parseIPv4(address) != null

    private fun isIPv6(address: String): Boolean = parseIPv6(address) != null

    private fun isValidAddress(bytes: ByteArray, includeLocalAddressesInNoderefs: Boolean): Boolean {
        if (isAnyLocalAddress(bytes)) return false

        if (isLinkLocalAddress(bytes) || isLoopbackAddress(bytes) || isSiteLocalAddress(bytes)) {
            return includeLocalAddressesInNoderefs
        }

        if (isMulticastAddress(bytes)) return false

        if (bytes.size == 4 && (bytes[0].toInt() and 0xFF) == 0) return false

        return true
    }

    private fun isSiteLocalAddress(address: ByteArray): Boolean {
        return when (address.size) {
            4 -> isIPv4SiteLocal(address)
            16 -> isIPv6SiteLocal(address)
            else -> false
        }
    }

    private fun isIPv4SiteLocal(address: ByteArray): Boolean {
        val b0 = address[0].toInt() and 0xFF
        val b1 = address[1].toInt() and 0xFF
        return b0 == 10 || (b0 == 172 && b1 in 16..31) || (b0 == 192 && b1 == 168)
    }

    private fun isIPv6SiteLocal(address: ByteArray): Boolean {
        val b0 = address[0].toInt() and 0xFF
        val b1 = address[1].toInt() and 0xFF
        return ((b0 and 0xFE) == 0xFC) || (b0 == 0xFE && (b1 and 0xC0) == 0xC0)
    }

    private fun parseAddress(address: String): ByteArray? {
        return if (address.contains(':')) parseIPv6(address) else parseIPv4(address)
    }

    private fun parseIPv4(address: String): ByteArray? {
        val parts = address.split('.')
        if (parts.size != 4) return null
        val res = ByteArray(4)
        for ((i, p) in parts.withIndex()) {
            val v = p.toIntOrNull() ?: return null
            if (v !in 0..255) return null
            res[i] = v.toByte()
        }
        return res
    }

    private fun parseIPv6(address: String): ByteArray? {
        val parts = address.split("::", limit = 2)
        val left = if (parts[0].isEmpty()) emptyList() else parts[0].split(':')
        val right = if (parts.size == 2 && parts[1].isNotEmpty()) parts[1].split(':') else emptyList()

        val total = left.size + right.size
        if (total > 8) return null
        val resParts = MutableList(8) { 0 }
        for (i in left.indices) {
            resParts[i] = parseHextet(left[i]) ?: return null
        }
        for (i in right.indices) {
            resParts[8 - right.size + i] = parseHextet(right[i]) ?: return null
        }

        var idx = 0
        val out = ByteArray(16)
        for (h in resParts) {
            out[idx++] = (h shr 8).toByte()
            out[idx++] = h.toByte()
        }
        return out
    }

    private fun parseHextet(part: String): Int? {
        val clean = part.ifEmpty { return null }
        val num = clean.toIntOrNull(16) ?: return null
        return if (num in 0..0xFFFF) num else null
    }

    private fun isAnyLocalAddress(address: ByteArray): Boolean = address.all { it.toInt() == 0 }

    private fun isLoopbackAddress(address: ByteArray): Boolean {
        return when (address.size) {
            4 -> (address[0].toInt() and 0xFF) == 127
            16 -> address.sliceArray(0 until 15).all { it.toInt() == 0 } && address[15].toInt() == 1
            else -> false
        }
    }

    private fun isLinkLocalAddress(address: ByteArray): Boolean {
        return when (address.size) {
            4 -> (address[0].toInt() and 0xFF) == 169 && (address[1].toInt() and 0xFF) == 254
            16 -> {
                val b0 = address[0].toInt() and 0xFF
                val b1 = address[1].toInt() and 0xFF
                b0 == 0xFE && (b1 and 0xC0) == 0x80
            }
            else -> false
        }
    }

    private fun isMulticastAddress(address: ByteArray): Boolean {
        return when (address.size) {
            4 -> (address[0].toInt() and 0xF0) == 0xE0
            16 -> (address[0].toInt() and 0xFF) == 0xFF
            else -> false
        }
    }
}


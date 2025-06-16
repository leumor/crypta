package network.crypta.support

import network.crypta.support.DataUtil.MULTIPLES
import network.crypta.support.DataUtil.bytesToDoubles
import network.crypta.support.DataUtil.bytesToInt
import network.crypta.support.DataUtil.bytesToInts
import network.crypta.support.DataUtil.bytesToLong
import network.crypta.support.DataUtil.bytesToLongs
import network.crypta.support.DataUtil.commaList
import network.crypta.support.DataUtil.compareVersion
import network.crypta.support.DataUtil.formatWithUnits
import network.crypta.support.DataUtil.hashCode
import network.crypta.support.DataUtil.intsToBytes
import network.crypta.support.DataUtil.longHashCode
import network.crypta.support.DataUtil.parseWithMultiplier
import network.crypta.support.DataUtil.textList
import kotlin.math.min

/**
 * A utility object providing a collection of functions for data manipulation.
 * This includes operations for converting between primitive types and byte arrays,
 * parsing strings into numbers (with support for unit multipliers), formatting numbers,
 * and comparing various data types like byte arrays and version strings.
 */
object DataUtil {
    /**
     * Stores numeric values for decimal (1000-based) and binary (1024-based) multipliers.
     * Used by [parseWithMultiplier] and [formatWithUnits].
     */
    private val MULTIPLES = longArrayOf(
        1000L,
        1L shl 10,
        1000L * 1000L,
        1L shl 20,
        1000L * 1000L * 1000L,
        1L shl 30,
        1000L * 1000L * 1000L * 1000L,
        1L shl 40,
        1000L * 1000L * 1000L * 1000L * 1000L,
        1L shl 50,
        1000L * 1000L * 1000L * 1000L * 1000L * 1000L,
        1L shl 60
    )

    /**
     * Stores string representations for unit multipliers corresponding to the values in [MULTIPLES].
     * Lowercase letters represent decimal multipliers, and uppercase letters represent binary multipliers.
     */
    private val MULTIPLES_2 = arrayOf(
        "k", "K", "m", "M", "g", "G", "t", "T", "p", "P", "e", "E"
    )

    /**
     * Converts a hexadecimal string to a [Long].
     * The string can have a maximum of 16 characters.
     *
     * @param hex The hexadecimal string to convert.
     * @return The resulting [Long] value.
     * @throws NumberFormatException if the string is empty, too long, or contains invalid hexadecimal characters.
     */
    fun hexToLong(hex: String): Long {
        val clean = hex.trim()
        if (clean.isEmpty()) throw NumberFormatException("Input hex string cannot be empty")
        if (clean.length > 16) throw NumberFormatException("Hex string exceeds maximum length")
        var result = 0L
        for (ch in clean) {
            val digit = ch.digitToIntOrNull(16)
                ?: throw NumberFormatException("Invalid hex character in string: $hex")
            result = (result shl 4) or digit.toLong()
        }
        return result
    }

    /**
     * Converts a hexadecimal string to an [Int].
     * The string can have a maximum of 8 characters.
     *
     * @param hex The hexadecimal string to convert.
     * @return The resulting [Int] value.
     * @throws NumberFormatException if the string is empty, too long, or contains invalid hexadecimal characters.
     */
    fun hexToInt(hex: String): Int {
        val clean = hex.trim()
        if (clean.isEmpty()) throw NumberFormatException("Hex string cannot be empty")
        if (clean.length > 16) throw NumberFormatException("Hex string cannot be longer than 16 characters")
        var result = 0
        for (ch in clean) {
            val digit =
                ch.digitToIntOrNull(16) ?: throw NumberFormatException("Invalid hex character: $ch")
            result = (result shl 4) or digit
        }
        return result
    }

    /**
     * Converts a string to a [Boolean], returning a default value if the string is null or not recognized.
     *
     * @param value The string to convert. Case-insensitive "true" returns true, "false" returns false.
     * @param def The default boolean value to return for null or unrecognized input.
     * @return The parsed [Boolean] or the default value.
     */
    fun stringToBool(value: String?, def: Boolean): Boolean {
        return when (value?.lowercase()) {
            "true" -> true
            "false" -> false
            else -> def
        }
    }

    /**
     * Converts a string to a [Boolean].
     * Accepts "true", "false", "yes", or "no" (case-insensitive).
     *
     * @param str The string to convert.
     * @return `true` if the string is "true" or "yes", `false` if it is "false" or "no".
     * @throws NumberFormatException if the input string is null or not one of the accepted values.
     */
    fun stringToBool(str: String?): Boolean {
        val s = str ?: throw NumberFormatException(
            """\
                Null input is not allowed.
                Please provide a valid boolean string representation.
            """.trimIndent()
        )
        return when {
            s.equals("false", ignoreCase = true) || s.equals("no", ignoreCase = true) -> false
            s.equals("true", ignoreCase = true) || s.equals("yes", ignoreCase = true) -> true
            else -> throw NumberFormatException(
                """
                Invalid boolean: $s
                Accepted values are: "true", "false", "yes", "no" (case-insensitive)
            """.trimIndent()
            )
        }
    }

    /**
     * Converts a [Boolean] to its string representation.
     *
     * @param b The boolean value.
     * @return "true" if the input is true, "false" otherwise.
     */
    fun boolToString(b: Boolean): String = if (b) "true" else "false"

    /**
     * Splits a comma-separated string into an array of trimmed strings.
     *
     * @param ls The comma-separated string.
     * @return An array of strings, or null if the input is null. Returns an empty array for an empty input string.
     */
    fun commaList(ls: String?): Array<String>? {
        return ls?.let { str ->
            if (str.isEmpty()) emptyArray() else str.split(',').map { it.trim() }.toTypedArray()
        }
    }

    /**
     * Joins an array of strings into a single comma-separated string.
     *
     * @param ls The array of strings to join.
     * @return A single string with elements separated by commas.
     * @see textList
     */
    fun commaList(ls: Array<String>): String = textList(ls, ',')

    /**
     * Joins an array of strings into a single string using a specified separator character.
     * Null elements in the array are treated as empty strings.
     *
     * @param ls The array of strings to join. Can be null or empty.
     * @param ch The character to use as a separator.
     * @return The joined string, or an empty string if the input array is null or empty.
     */
    fun textList(ls: Array<String>?, ch: Char): String {
        if (ls == null || ls.isEmpty()) return ""
        return ls.joinToString(ch.toString()) { it }
    }

    /**
     * Joins an array of objects into a single comma-separated string by calling `toString()` on each object.
     *
     * @param objects The array of objects to join.
     * @return A single string with elements separated by commas.
     * @see commaList
     */
    fun commaList(objects: Array<Any?>): String = commaList(objects, ',')

    /**
     * Joins an array of objects into a single string using a specified separator.
     * `toString()` is called on each object. Null objects are represented as empty strings.
     *
     * @param objects The array of objects to join. Can be null or empty.
     * @param separator The character to use as a separator.
     * @return The joined string, or an empty string if the input array is null or empty.
     * @throws IllegalArgumentException if the separator is a control character.
     */
    fun commaList(objects: Array<Any?>?, separator: Char): String {
        if (objects == null || objects.isEmpty()) return ""
        require(!separator.isISOControl()) { "Separator cannot be a control character" }
        return buildString {
            for ((i, obj) in objects.withIndex()) {
                if (i > 0) append(separator)
                append(obj ?: "")
            }
        }
    }

    /**
     * Compares two byte arrays lexicographically.
     * Compares byte by byte, treating them as unsigned values. If one array is a prefix of the other,
     * the shorter array is considered smaller.
     *
     * @param a The first byte array.
     * @param b The second byte array.
     * @return A negative integer, zero, or a positive integer as the first array
     *         is less than, equal to, or greater than the second.
     */
    fun compareBytes(a: ByteArray, b: ByteArray): Int {
        val min = min(a.size, b.size)
        for (i in 0 until min) {
            val x = a[i].toInt() and 0xff
            val y = b[i].toInt() and 0xff
            if (x != y) return x.compareTo(y)
        }
        return a.size.compareTo(b.size)
    }

    /**
     * Checks for equality between segments of two byte arrays.
     *
     * @param a The first byte array.
     * @param b The second byte array.
     * @param aoff The starting offset in the first array.
     * @param boff The starting offset in the second array.
     * @param len The number of bytes to compare.
     * @return `true` if the specified segments are equal, `false` otherwise.
     * @throws IllegalArgumentException if any offset or length is negative.
     */
    fun byteArrayEqual(a: ByteArray, b: ByteArray, aoff: Int, boff: Int, len: Int): Boolean {
        require(aoff >= 0 && boff >= 0 && len >= 0) { "Offset and length must be non-negative" }
        if (aoff + len > a.size || boff + len > b.size) return false
        for (i in 0 until len) {
            if (a[aoff + i] != b[boff + i]) return false
        }
        return true
    }

    /**
     * Computes an integer hash code for a byte array.
     *
     * @param bytes The byte array to hash.
     * @return The integer hash code.
     * @see hashCode
     */
    fun hashCode(bytes: ByteArray): Int = hashCode(bytes, 0, bytes.size)

    /**
     * Computes an integer hash code for a segment of a byte array.
     *
     * @param bytes The byte array.
     * @param offset The starting offset of the segment.
     * @param length The length of the segment.
     * @return The integer hash code.
     * @throws IllegalArgumentException if offset or length is negative, or if the segment is out of bounds.
     */
    fun hashCode(bytes: ByteArray, offset: Int, length: Int): Int {
        require(offset >= 0) { "Offset cannot be negative" }
        require(length >= 0) { "Length cannot be negative" }
        require(offset + length <= bytes.size) { "Offset + length exceeds array bounds" }
        var hash = 0
        for (i in length - 1 downTo 0) {
            val value = bytes[offset + i].toInt() and 0xff
            hash = hash xor (value shl ((i and 3) shl 3))
        }
        return hash
    }

    /**
     * Computes a long hash code for a byte array.
     *
     * @param bytes The byte array to hash.
     * @return The long hash code.
     * @see longHashCode
     */
    fun longHashCode(bytes: ByteArray): Long = longHashCode(bytes, 0, bytes.size)

    /**
     * Computes a long hash code for a segment of a byte array.
     *
     * @param bytes The byte array.
     * @param offset The starting offset of the segment.
     * @param length The length of the segment.
     * @return The long hash code.
     * @throws IllegalArgumentException if offset or length is negative, or if the segment is out of bounds.
     */
    fun longHashCode(bytes: ByteArray, offset: Int, length: Int): Long {
        require(offset >= 0) { "Offset cannot be negative" }
        require(length >= 0) { "Length cannot be negative" }
        require(offset + length <= bytes.size) { "Offset + length exceeds array bounds" }
        var hash = 0L
        for (i in length - 1 downTo 0) {
            val value = bytes[offset + i].toInt() and 0xff
            val shift = (i and 7) shl 3
            hash = hash xor (value.toLong() shl shift)
        }
        return hash
    }

    /**
     * Converts an array of [Long] values into a single byte array (little-endian).
     *
     * @param longs The array of longs to convert.
     * @return The resulting byte array.
     * @throws IllegalArgumentException if the input array is too large.
     */
    fun longsToBytes(longs: LongArray): ByteArray {
        require(longs.size <= Int.MAX_VALUE / 8) { "Input array too large" }
        val res = ByteArray(longs.size * 8)
        var index = 0
        for (value in longs) {
            val b = longToBytes(value)
            b.copyInto(res, index)
            index += 8
        }
        return res
    }

    /**
     * Converts a byte array into an array of [Long] values.
     *
     * @param buf The byte array to convert. Its length must be a multiple of 8.
     * @return The resulting array of longs.
     * @see bytesToLongs
     */
    fun bytesToLongs(buf: ByteArray): LongArray = bytesToLongs(buf, 0, buf.size)

    /**
     * Converts a segment of a byte array into an array of [Long] values (little-endian).
     *
     * @param buf The source byte array.
     * @param offset The starting offset in the byte array.
     * @param length The number of bytes to convert, which must be a multiple of 8.
     * @return The resulting array of longs.
     * @throws IllegalArgumentException if length is not a multiple of 8, or if the segment is out of bounds.
     */
    fun bytesToLongs(buf: ByteArray, offset: Int, length: Int): LongArray {
        require(length % 8 == 0) { "Length must be a multiple of 8" }
        require(offset >= 0 && length >= 0 && offset + length <= buf.size) { "Invalid offset or length parameters" }
        val longs = LongArray(length / 8)
        for (i in longs.indices) {
            longs[i] = bytesToLong(buf, offset + i * 8)
        }
        return longs
    }

    /**
     * Converts the first 8 bytes of a byte array to a [Long] (little-endian).
     *
     * @param bytes The byte array, must be at least 8 bytes long.
     * @return The resulting [Long].
     * @see bytesToLong
     */
    fun bytesToLong(bytes: ByteArray): Long = bytesToLong(bytes, 0)

    /**
     * Converts 8 bytes from a byte array at a specified offset to a [Long] (little-endian).
     *
     * @param bytes The source byte array.
     * @param offset The starting offset in the byte array.
     * @return The resulting [Long].
     * @throws IllegalArgumentException if offset is negative or there are insufficient bytes.
     */
    fun bytesToLong(bytes: ByteArray, offset: Int): Long {
        require(offset >= 0) { "Offset cannot be negative" }
        require(bytes.size >= offset + 8) { "Insufficient bytes available" }
        var result = 0L
        for (i in 7 downTo 0) {
            result = (result shl 8) or (bytes[offset + i].toLong() and 0xff)
        }
        return result
    }

    /**
     * Converts the first 4 bytes of a byte array to an [Int] (little-endian).
     *
     * @param bytes The byte array, must be at least 4 bytes long.
     * @return The resulting [Int].
     * @see bytesToInt
     */
    fun bytesToInt(bytes: ByteArray): Int = bytesToInt(bytes, 0)

    /**
     * Converts 4 bytes from a byte array at a specified offset to an [Int] (little-endian).
     *
     * @param bytes The source byte array.
     * @param offset The starting offset in the byte array.
     * @return The resulting [Int].
     * @throws IllegalArgumentException if offset is negative or there are insufficient bytes.
     */
    fun bytesToInt(bytes: ByteArray, offset: Int): Int {
        require(offset >= 0) { "Offset cannot be negative" }
        require(bytes.size >= offset + 4) { "Insufficient bytes available" }
        var result = 0
        for (i in 3 downTo 0) {
            result = (result shl 8) or (bytes[offset + i].toInt() and 0xff)
        }
        return result
    }

    /**
     * Converts 2 bytes from a byte array at a specified offset to a [Short] (little-endian).
     *
     * @param buf The source byte array.
     * @param offset The starting offset in the byte array.
     * @return The resulting [Short].
     * @throws IllegalArgumentException if offset is negative or there are insufficient bytes.
     */
    fun bytesToShort(buf: ByteArray, offset: Int): Short {
        require(offset >= 0 && buf.size >= offset + 2) {
            "Invalid buffer length or offset. Required: offset >= 0 and buf.length >= offset + 2"
        }
        val low = buf[offset].toInt() and 0xff
        val high = buf[offset + 1].toInt() and 0xff
        return ((high shl 8) or low).toShort()
    }

    /**
     * Converts a segment of a byte array into an array of [Int] values (little-endian).
     *
     * @param buf The source byte array.
     * @param offset The starting offset in the byte array.
     * @param length The number of bytes to convert, which must be a multiple of 4.
     * @return The resulting array of ints.
     * @throws IllegalArgumentException if length is not a multiple of 4, or if the segment is out of bounds.
     */
    fun bytesToInts(buf: ByteArray, offset: Int, length: Int): IntArray {
        require(length % 4 == 0) { "Length must be a multiple of 4" }
        require(offset >= 0 && length >= 0 && offset + length <= buf.size) { "Invalid offset or length" }
        val ints = IntArray(length / 4)
        for (i in ints.indices) {
            ints[i] = bytesToInt(buf, offset + i * 4)
        }
        return ints
    }

    /**
     * Converts a byte array into an array of [Int] values.
     *
     * @param buf The byte array to convert. Its length must be a multiple of 4.
     * @return The resulting array of ints.
     * @see bytesToInts
     */
    fun bytesToInts(buf: ByteArray): IntArray = bytesToInts(buf, 0, buf.size)

    /**
     * Converts a [Long] value into an 8-byte array (little-endian).
     *
     * @param value The long to convert.
     * @return The resulting 8-byte array.
     */
    fun longToBytes(value: Long): ByteArray {
        val res = ByteArray(8)
        for (i in 0 until 8) {
            res[i] = ((value shr (8 * i)) and 0xff).toByte()
        }
        return res
    }

    /**
     * Converts an array of [Int] values into a single byte array.
     *
     * @param ints The array of ints to convert.
     * @return The resulting byte array.
     * @see intsToBytes
     */
    fun intsToBytes(ints: IntArray): ByteArray = intsToBytes(ints, 0, ints.size)

    /**
     * Converts a segment of an [Int] array into a single byte array (little-endian).
     *
     * @param ints The source array of ints.
     * @param offset The starting offset in the int array.
     * @param length The number of ints to convert.
     * @return The resulting byte array.
     * @throws IllegalArgumentException if the segment is out of bounds.
     */
    fun intsToBytes(ints: IntArray, offset: Int, length: Int): ByteArray {
        require(offset >= 0 && length >= 0 && offset + length <= ints.size) { "Invalid offset or length" }
        val res = ByteArray(length * 4)
        for (i in 0 until length) {
            val b = intToBytes(ints[offset + i])
            b.copyInto(res, i * 4)
        }
        return res
    }

    /**
     * Converts an [Int] value into a 4-byte array (little-endian).
     *
     * @param value The int to convert.
     * @return The resulting 4-byte array.
     */
    fun intToBytes(value: Int): ByteArray {
        val res = ByteArray(4)
        for (i in 0 until 4) {
            res[i] = ((value shr (8 * i)) and 0xff).toByte()
        }
        return res
    }

    /**
     * Converts a [Short] value into a 2-byte array (little-endian).
     *
     * @param value The short to convert.
     * @return The resulting 2-byte array.
     */
    fun shortToBytes(value: Short): ByteArray {
        val res = ByteArray(2)
        res[0] = (value.toInt() and 0xff).toByte()
        res[1] = ((value.toInt() shr 8) and 0xff).toByte()
        return res
    }

    /**
     * Parses a string with an optional unit multiplier (e.g., "10k", "2M", "1G") into a [Short].
     *
     * @param s The string to parse.
     * @return The parsed [Short] value.
     * @throws NumberFormatException if the string is not a valid number or is out of [Short] range.
     * @see parseWithMultiplier
     */
    fun parseShort(s: String): Short {
        val value = parseWithMultiplier(s)
        if (value > Short.MAX_VALUE || value < Short.MIN_VALUE) throw NumberFormatException("Value out of range for short: $value")
        return value.toInt().toShort()
    }

    /**
     * Parses a string with an optional unit multiplier (e.g., "10k", "2M", "1G") into an [Int].
     *
     * @param s The string to parse.
     * @return The parsed [Int] value.
     * @throws NumberFormatException if the string is not a valid number or is out of [Int] range.
     * @see parseWithMultiplier
     */
    fun parseInt(s: String): Int {
        val value = parseWithMultiplier(s)
        if (value > Int.MAX_VALUE || value < Int.MIN_VALUE) throw NumberFormatException("Value out of range for int: $value")
        return value.toInt()
    }

    /**
     * Parses a string with an optional unit multiplier (e.g., "10k", "2M", "1G") into a [Long].
     *
     * @param s The string to parse.
     * @return The parsed [Long] value.
     * @throws NumberFormatException if the string is not a valid number or is out of [Long] range.
     * @see parseWithMultiplier
     */
    fun parseLong(s: String): Long {
        val value = parseWithMultiplier(s)
        if (value > Long.MAX_VALUE || value < Long.MIN_VALUE) throw NumberFormatException("Value out of range for long: $value")
        return value.toLong()
    }

    /**
     * Formats a [Number] ([Long], [Int], or [Short]) into a string with appropriate units.
     *
     * @param T The type of the number, must be a subtype of [Number].
     * @param value The number to format.
     * @param isSize If true, binary (KiB, MiB) units may be used. If false, only decimal (k, m) units are used.
     * @return A string representation of the number with units (e.g., "1024" -> "1KiB").
     * @throws IllegalArgumentException if the number type is not supported.
     */
    fun <T : Number> numberToString(value: T, isSize: Boolean): String {
        val longVal = when (value) {
            is Long -> value
            is Int -> value.toLong()
            is Short -> value.toLong()
            else -> throw IllegalArgumentException("Unsupported number type: ${value::class}")
        }
        return formatWithUnits(longVal, isSize)
    }

    /**
     * Formats a [Long] into a string with appropriate units.
     *
     * @param value The number to format.
     * @param isSize If true, binary (KiB, MiB) units may be used. If false, only decimal (k, m) units are used.
     * @return A string representation of the number with units (e.g., "1024" -> "1KiB").
     */
    fun longToString(value: Long, isSize: Boolean): String = formatWithUnits(value, isSize)

    /**
     * Formats an [Int] into a string with appropriate units.
     *
     * @param value The number to format.
     * @param isSize If true, binary (KiB, MiB) units may be used. If false, only decimal (k, m) units are used.
     * @return A string representation of the number with units (e.g., "1024" -> "1KiB").
     */
    fun intToString(value: Int, isSize: Boolean): String = formatWithUnits(value.toLong(), isSize)

    /**
     * Formats a [Short] into a string with appropriate units.
     *
     * @param value The number to format.
     * @param isSize If true, binary (KiB, MiB) units may be used. If false, only decimal (k, m) units are used.
     * @return A string representation of the number with units.
     */
    fun shortToString(value: Short, isSize: Boolean): String =
        formatWithUnits(value.toLong(), isSize)

    /**
     * Converts a segment of a byte array into an array of [Double] values.
     * Each double is constructed from 8 bytes using `Double.fromBits`.
     *
     * @param data The source byte array.
     * @param offset The starting offset in the byte array.
     * @param length The number of bytes to convert, must be a multiple of 8.
     * @return An array of [Double] values.
     * @throws IllegalArgumentException if the segment is out of bounds or its length is not a multiple of 8.
     */
    fun bytesToDoubles(data: ByteArray, offset: Int, length: Int): DoubleArray {
        require(offset >= 0 && length >= 0 && offset + length <= data.size) { "Invalid offset or length" }
        require(length % 8 == 0) { "Length must be a multiple of 8" }
        val longs = bytesToLongs(data, offset, length)
        return DoubleArray(longs.size) { Double.fromBits(longs[it]) }
    }

    /**
     * Converts an array of [Double] values into a byte array.
     * Each double is converted to its 8-byte `Long` bit representation using `toBits`.
     *
     * @param doubles The array of doubles to convert.
     * @return The resulting byte array.
     */
    fun doublesToBytes(doubles: DoubleArray): ByteArray {
        val longs = LongArray(doubles.size) { doubles[it].toBits() }
        return longsToBytes(longs)
    }

    /**
     * Converts a byte array into an array of [Double] values.
     * The length of the byte array must be a multiple of 8.
     *
     * @param data The byte array to convert.
     * @return An array of [Double] values.
     * @see bytesToDoubles
     */
    fun bytesToDoubles(data: ByteArray): DoubleArray = bytesToDoubles(data, 0, data.size)

    /**
     * Trims each line in a given string, removes any resulting empty lines,
     * and joins them back together with newline characters.
     *
     * @param str The string to process. Can be null.
     * @return The processed string, or an empty string if the input is null.
     */
    fun trimLines(str: String?): String {
        if (str == null) return ""
        return buildString {
            str.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }
                .forEach { append(it).append('\n') }
        }
    }

    /**
     * Compares two version strings (e.g., "1.2.alpha" vs "1.3.0").
     * The comparison alternates between numeric and alphabetic segments.
     *
     * @param x The first version string.
     * @param y The second version string.
     * @return a negative integer, zero, or a positive integer as the first version
     *         is less than, equal to, or greater than the second.
     */
    fun compareVersion(x: String, y: String): Int {
        var i = 0
        var j = 0
        var wantDigits = false
        while (i < x.length || j < y.length) {
            val xStart = i
            val yStart = j
            i += getDigits(x, i, wantDigits)
            j += getDigits(y, j, wantDigits)
            val xSeg = x.substring(xStart, min(i, x.length))
            val ySeg = y.substring(yStart, min(j, y.length))
            if (wantDigits) {
                when {
                    xSeg.isEmpty() && ySeg.isEmpty() -> {
                        // continue
                    }

                    xSeg.isEmpty() -> {
                        return -1
                    }

                    ySeg.isEmpty() -> {
                        return 1
                    }

                    else -> {
                        val a = xSeg.toLongOrNull()
                        val b = ySeg.toLongOrNull()
                        if (a != null && b != null) {
                            val result = a.compareTo(b)
                            if (result != 0) return result
                            val lenComp = xSeg.length.compareTo(ySeg.length)
                            if (lenComp != 0) return -lenComp
                        } else {
                            val result = xSeg.compareTo(ySeg)
                            if (result != 0) return result
                        }
                    }
                }
            } else {
                val result = xSeg.compareTo(ySeg)
                if (result != 0) return result
            }
            wantDigits = !wantDigits
        }
        return 0
    }

    /**
     * Compares two objects based on their identity hash code for ordering.
     * Note: Kotlin/Native doesn't expose `System.identityHashCode`, so this falls back
     * to the regular `hashCode` for cross-platform compatibility. This may not provide
     * a stable ordering across different platforms or executions for objects that
     * implement `hashCode`.
     *
     * @param o1 The first object.
     * @param o2 The second object.
     * @return A negative integer, zero, or a positive integer as the first object's
     *         hash code is less than, equal to, or greater than the second's.
     */
    fun compareObjectID(o1: Any?, o2: Any?): Int {
        // Kotlin/Native doesn't expose System.identityHashCode, so fall back to
        // the regular hashCode implementation for cross-platform support.
        val h1 = o1?.hashCode() ?: 0
        val h2 = o2?.hashCode() ?: 0
        return h1.compareTo(h2)
    }

    /**
     * A utility function to compare two integers. Syntactic sugar for `x.compareTo(y)`.
     * @return The result of `x.compareTo(y)`.
     */
    fun compare(x: Int, y: Int): Int = x.compareTo(y)

    /**
     * A utility function to compare two longs. Syntactic sugar for `x.compareTo(y)`.
     * @return The result of `x.compareTo(y)`.
     */
    fun compare(x: Long, y: Long): Int = x.compareTo(y)

    /**
     * A utility function to compare two doubles. Syntactic sugar for `x.compareTo(y)`.
     * @return The result of `x.compareTo(y)`.
     */
    fun compare(x: Double, y: Double): Int = x.compareTo(y)

    /**
     * A utility function to compare two floats. Syntactic sugar for `x.compareTo(y)`.
     * @return The result of `x.compareTo(y)`.
     */
    fun compare(x: Float, y: Float): Int = x.compareTo(y)

    /**
     * Compares two [Comparable] objects, gracefully handling nulls.
     * A null value is considered smaller than any non-null value.
     *
     * @param T The type of the objects to compare.
     * @param a The first object.
     * @param b The second object.
     * @return A negative integer, zero, or a positive integer.
     */
    fun <T : Comparable<T>> compare(a: T?, b: T?): Int {
        return when {
            a == null && b == null -> 0
            a == null -> -1
            b == null -> 1
            else -> a.compareTo(b)
        }
    }

    /**
     * Creates a copy of a sub-array of a byte array.
     *
     * @param buf The source byte array.
     * @param offset The starting position in the source array. Defaults to 0.
     * @param length The number of elements to copy. Defaults to the rest of the array.
     * @return A new byte array containing the specified sub-array.
     * @throws IllegalArgumentException if the range is invalid.
     */
    fun copyToArray(buf: ByteArray, offset: Int = 0, length: Int = buf.size - offset): ByteArray {
        require(offset >= 0 && length >= 0 && offset + length <= buf.size)
        return buf.copyOfRange(offset, offset + length)
    }

    /**
     * Helper function for [compareVersion]. Gets the length of a continuous sequence of
     * digits or non-digits from a starting point in a string.
     *
     * @param str The string to scan.
     * @param start The starting index.
     * @param wantDigits `true` to scan for digits, `false` to scan for non-digits.
     * @return The number of characters in the sequence.
     */
    fun getDigits(str: String, start: Int, wantDigits: Boolean): Int {
        var i = start
        while (i < str.length) {
            if (str[i].isDigit() != wantDigits) break
            i++
        }
        return i - start
    }

    /**
     * Private helper to format a long value with the most appropriate unit.
     * It simplifies the value if it's an exact multiple of a known unit.
     *
     * @param value The numeric value to format.
     * @param isSize If true, binary units (KiB, MiB) are preferred. Otherwise, decimal units are used.
     * @return The formatted string with a unit suffix (e.g., "10M", "2KiB") or the original number as a string.
     */
    private fun formatWithUnits(value: Long, isSize: Boolean): String {
        if (value <= 0) return value.toString()
        for (i in MULTIPLES.lastIndex downTo 0) {
            val mult = MULTIPLES[i]
            if (value >= mult && value % mult == 0L) {
                val isDecimal = mult % 1000L == 0L
                if (isSize || isDecimal) {
                    val suffix = MULTIPLES_2[i]
                    val binary = suffix[0].isUpperCase()
                    val unit = value / mult
                    return unit.toString() + suffix + if (binary) "iB" else ""
                }
            }
        }
        return value.toString()
    }

    /**
     * Private helper to parse a string that may contain a unit multiplier suffix.
     * Handles suffixes like 'k', 'K', 'm', 'M', 'B', 'iB'.
     *
     * @param s The string to parse.
     * @return The parsed numeric value as a [Double].
     * @throws NumberFormatException if the string is empty or malformed.
     */
    private fun parseWithMultiplier(s: String): Double {
        var normalized = s.trim()
        if (normalized.endsWith("iB")) {
            normalized = normalized.dropLast(2)
        } else if (normalized.endsWith("B")) {
            normalized = normalized.dropLast(1)
        }
        normalized = normalized.trim()
        if (normalized.isEmpty()) throw NumberFormatException("Input string is empty after removing suffix")
        var multiplier = 1L
        var end = normalized.length
        val last = normalized.last()
        val idx = "kKmMgGtTpPeE".indexOf(last)
        if (idx != -1) {
            multiplier = MULTIPLES[idx]
            end--
        }
        val numeric = normalized.substring(0, end).trim()
        if (numeric.isEmpty()) {
            return multiplier.toDouble()
        }
        val base = numeric.toDouble()
        return base * multiplier
    }
}


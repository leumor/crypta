package network.crypta.support

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@OptIn(ExperimentalStdlibApi::class)
class DataUtilsTest {

    @Test
    fun testHexToLong() {
        var l = DataUtil.hexToLong("0")
        assertEquals(0L, l)

        l = DataUtil.hexToLong("000000")
        assertEquals(0L, l)

        l = DataUtil.hexToLong("1")
        assertEquals(1L, l)

        l = DataUtil.hexToLong("a")
        assertEquals(10L, l)

        l = DataUtil.hexToLong("ff")
        assertEquals(255L, l)

        l = DataUtil.hexToLong("ffffffff")
        assertEquals(4294967295L, l)

        l = DataUtil.hexToLong("7fffffffffffffff")
        assertEquals(Long.MAX_VALUE, l)

        l = DataUtil.hexToLong("8000000000000000")
        assertEquals(Long.MIN_VALUE, l)

        l = DataUtil.hexToLong("FFfffFfF")
        assertEquals(4294967295L, l)

        assertFailsWith<NumberFormatException> { DataUtil.hexToLong("abcdef123456789aa") }
        assertFailsWith<NumberFormatException> { DataUtil.hexToLong("DeADC0dER") }

        l = DataUtil.hexToLong(20L.toHexString())
        assertEquals(20L, l)

        val temp = Long.MIN_VALUE.toHexString()
        l = DataUtil.hexToLong(Long.MIN_VALUE.toHexString())
        assertEquals(Long.MIN_VALUE, l)

        val longAsString = (-1L).toString(16)
        assertFailsWith<NumberFormatException> { DataUtil.hexToLong(longAsString) }
    }

    @Test
    fun testHexToInt() {
        var i = DataUtil.hexToInt("0")
        assertEquals(0, i)

        i = DataUtil.hexToInt("000000")
        assertEquals(0, i)

        i = DataUtil.hexToInt("1")
        assertEquals(1, i)

        i = DataUtil.hexToInt("a")
        assertEquals(10, i)

        i = DataUtil.hexToInt("ff")
        assertEquals(255, i)

        i = DataUtil.hexToInt("80000000")
        assertEquals(Int.MIN_VALUE, i)

        i = DataUtil.hexToInt("0000000080000000")
        assertEquals(Int.MIN_VALUE, i)

        i = DataUtil.hexToInt("7fffffff")
        assertEquals(Int.MAX_VALUE, i)

        assertFailsWith<NumberFormatException> { DataUtil.hexToInt("0123456789abcdef0") }
        assertFailsWith<NumberFormatException> { DataUtil.hexToInt("C0dER") }

        i = DataUtil.hexToInt(20L.toHexString())
        assertEquals(20, i)

        i = DataUtil.hexToInt(Int.MIN_VALUE.toHexString())
        assertEquals(Int.MIN_VALUE, i)

        val intAsString = (-1).toString(16)
        assertFailsWith<NumberFormatException> { DataUtil.hexToInt(intAsString) }
    }

    @Test
    fun testStringToBool() {
        assertTrue(DataUtil.stringToBool("true"))
        assertTrue(DataUtil.stringToBool("TRUE"))
        assertFalse(DataUtil.stringToBool("false"))
        assertFalse(DataUtil.stringToBool("FALSE"))

        assertFailsWith<NumberFormatException> { DataUtil.stringToBool("Free Tibet") }
        assertFailsWith<NumberFormatException> { DataUtil.stringToBool(null) }
    }

    @Test
    fun testStringToBoolWithDefault() {
        assertTrue(DataUtil.stringToBool("true", false))
        assertFalse(DataUtil.stringToBool("false", true))
        assertTrue(DataUtil.stringToBool("TruE", false))
        assertFalse(DataUtil.stringToBool("faLSE", true))
        assertTrue(DataUtil.stringToBool("trueXXX", true))
        assertFalse(DataUtil.stringToBool("XXXFalse", false))
        assertTrue(DataUtil.stringToBool(null, true))
    }

    @Test
    fun testBoolToString() {
        assertEquals("true", DataUtil.boolToString(true))
        assertEquals("false", DataUtil.boolToString(false))
    }

    @Test
    fun testCommaListFromString() {
        val expected = arrayOf("one", "two", "three", "four")
        val actual = DataUtil.commaList("one,two,     three    ,  four")
        assertNotNull(actual)
        assertContentEquals(expected, actual)

        assertNull(DataUtil.commaList(null as String?))

        val emptyActual = DataUtil.commaList("")
        assertNotNull(emptyActual)
        assertEquals(0, emptyActual.size)
    }

    @Test
    fun testStringArrayToCommaList() {
        var input = arrayOf("one", "two", "three", "four")
        var expected = "one,two,three,four"
        var actual = DataUtil.commaList(input)
        assertEquals(expected, actual)

        input = emptyArray()
        expected = ""
        actual = DataUtil.commaList(input)
        assertEquals(expected, actual)
    }

    @Test
    fun testHashcodeForByteArray() {
        var arr = ByteArray(8) { it.toByte() }
        assertEquals(67372036, DataUtil.hashCode(arr))

        arr = byteArrayOf()
        assertEquals(0, DataUtil.hashCode(arr))
    }

    @Test
    fun testLongHashcode() {
        val b1 = byteArrayOf(1, 1, 2, 2, 3, 3)
        val b2 = byteArrayOf(2, 2, 3, 3, 4, 4)
        val b3 = byteArrayOf(1, 1, 2, 2, 3, 3)

        val l1 = DataUtil.longHashCode(b1)
        val l2 = DataUtil.longHashCode(b2)
        val l3 = DataUtil.longHashCode(b3)

        assertNotEquals(l1, l2)
        assertNotEquals(l2, l3)
        assertEquals(l1, l3)
    }

    @Test
    fun testIntsToBytes() {
        var ints = intArrayOf()
        doRoundTripIntsArrayToBytesArray(ints)

        ints = intArrayOf(Int.MIN_VALUE)
        doRoundTripIntsArrayToBytesArray(ints)

        ints = intArrayOf(0, Int.MAX_VALUE, Int.MIN_VALUE)
        doRoundTripIntsArrayToBytesArray(ints)

        ints = intArrayOf(33685760, 51511577)
        doRoundTripIntsArrayToBytesArray(ints)
    }

    @Test
    fun testBytesToLongsException() {
        val bytes = ByteArray(3)
        assertFailsWith<IllegalArgumentException> { DataUtil.bytesToLongs(bytes, 0, bytes.size) }
    }

    @Test
    fun testBytesToInt() {
        val bytes = byteArrayOf(0, 1, 2, 2)
        val outInt = DataUtil.bytesToInt(bytes, 0)
        assertEquals(33685760, outInt)
        doTestRoundTripBytesArrayToInt(bytes)

        val finalBytes = byteArrayOf()
        assertFailsWith<IllegalArgumentException> { doTestRoundTripBytesArrayToInt(finalBytes) }

        val b2 = byteArrayOf(1, 1, 1, 1)
        doTestRoundTripBytesArrayToInt(b2)
    }

    @Test
    fun testLongsToBytes() {
        var longs = longArrayOf()
        doRoundTripLongsArrayToBytesArray(longs)

        longs = longArrayOf(Long.MIN_VALUE)
        doRoundTripLongsArrayToBytesArray(longs)

        longs = longArrayOf(0L, Long.MAX_VALUE, Long.MIN_VALUE)
        doRoundTripLongsArrayToBytesArray(longs)

        longs = longArrayOf(3733393793879837L)
        doRoundTripLongsArrayToBytesArray(longs)
    }

    @Test
    fun testBytesToLongException() {
        val bytes = ByteArray(3)
        assertFailsWith<IllegalArgumentException> { DataUtil.bytesToLong(bytes, 0) }
    }

    @Test
    fun testBytesToLong() {
        var bytes = byteArrayOf(0, 1, 2, 2, 1, 3, 6, 7)
        val out = DataUtil.bytesToLong(bytes)
        assertEquals(506095310989295872L, out)
        doTestRoundTripBytesArrayToLong(bytes)

        val empty = byteArrayOf()
        assertFailsWith<IllegalArgumentException> { doTestRoundTripBytesArrayToLong(empty) }

        bytes = byteArrayOf(1, 1, 1, 1, 1, 1, 1, 1)
        doTestRoundTripBytesArrayToLong(bytes)
    }

    @Test
    fun testTrimLines() {
        assertEquals("", DataUtil.trimLines(""))
        assertEquals("", DataUtil.trimLines("\n"))
        assertEquals("a\n", DataUtil.trimLines("a"))
        assertEquals("a\n", DataUtil.trimLines("a\n"))
        assertEquals("a\n", DataUtil.trimLines(" a\n"))
        assertEquals("a\n", DataUtil.trimLines(" a \n"))
        assertEquals("a\n", DataUtil.trimLines(" a\n"))
        assertEquals("a\n", DataUtil.trimLines("\na"))
        assertEquals("a\n", DataUtil.trimLines("\na\n"))
        assertEquals("a\nb\n", DataUtil.trimLines("a\nb"))
    }

    @Test
    fun testGetDigits() {
        assertEquals(1, DataUtil.getDigits("1.0", 0, true))
        assertEquals(0, DataUtil.getDigits("1.0", 0, false))
        assertEquals(1, DataUtil.getDigits("1.0", 1, false))
        assertEquals(0, DataUtil.getDigits("1.0", 1, true))
        assertEquals(1, DataUtil.getDigits("1.0", 2, true))
        assertEquals(0, DataUtil.getDigits("1.0", 2, false))

        val r = Random(88888)
        repeat(1024) {
            val digits = r.nextInt(20) + 1
            val nonDigits = r.nextInt(20) + 1
            val digits2 = r.nextInt(20) + 1
            val s = generateDigits(r, digits) + generateNonDigits(r, nonDigits) + generateDigits(
                r,
                digits2
            )
            assertEquals(0, DataUtil.getDigits(s, 0, false))
            assertEquals(digits, DataUtil.getDigits(s, 0, true))
            assertEquals(nonDigits, DataUtil.getDigits(s, digits, false))
            assertEquals(0, DataUtil.getDigits(s, digits, true))
            assertEquals(digits2, DataUtil.getDigits(s, digits + nonDigits, true))
            assertEquals(0, DataUtil.getDigits(s, digits + nonDigits, false))
        }
    }

    @Test
    fun testCompareVersion() {
        checkCompareVersionLessThan("1.0", "1.1")
        checkCompareVersionLessThan("1.0", "1.01")
        checkCompareVersionLessThan("1.0", "2.0")
        checkCompareVersionLessThan("1.0", "11.0")
        checkCompareVersionLessThan("1.0", "1.0.1")
        checkCompareVersionLessThan("1", "1.1")
        checkCompareVersionLessThan("1", "2")
        checkCompareVersionLessThan("test 1.0", "test 1.1")
        checkCompareVersionLessThan("best 1.0", "test 1.0")
        checkCompareVersionLessThan("test 1.0", "testing 1.0")
        checkCompareVersionLessThan("1.0", "test 1.0")
    }

    @Test
    fun testStringToLongOverflow() {
        assertFailsWith<NumberFormatException> { DataUtil.parseLong("9999999999GiB") }
    }

    private fun doRoundTripIntsArrayToBytesArray(ints: IntArray) {
        val bytes = DataUtil.intsToBytes(ints)
        assertEquals(bytes.size, ints.size * 4)
        val out = DataUtil.bytesToInts(bytes)
        assertContentEquals(ints, out)
    }

    private fun doTestRoundTripBytesArrayToInt(bytes: ByteArray) {
        val out = DataUtil.bytesToInt(bytes, 0)
        val back = DataUtil.intToBytes(out)
        assertContentEquals(bytes, back)
    }

    private fun doRoundTripLongsArrayToBytesArray(longs: LongArray) {
        val bytes = DataUtil.longsToBytes(longs)
        assertEquals(bytes.size, longs.size * 8)
        val out = DataUtil.bytesToLongs(bytes)
        assertContentEquals(longs, out)
    }

    private fun doTestRoundTripBytesArrayToLong(bytes: ByteArray) {
        val out = DataUtil.bytesToLong(bytes)
        val back = DataUtil.longToBytes(out)
        assertContentEquals(bytes, back)
    }

    private fun generateDigits(r: Random, count: Int): String = buildString {
        repeat(count) { append(('0'.code + r.nextInt(10)).toChar()) }
    }

    private fun generateNonDigits(r: Random, count: Int): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyz"
        val nonDigits = "./\\_=:+" + alphabet + alphabet.uppercase()
        return buildString {
            repeat(count) { append(nonDigits[r.nextInt(nonDigits.length)]) }
        }
    }

    private fun checkCompareVersionLessThan(a: String, b: String) {
        checkCompareVersionEquals(a, a)
        checkCompareVersionEquals(b, b)
        assertTrue(DataUtil.compareVersion(a, b) < 0)
        assertTrue(DataUtil.compareVersion(b, a) > 0)
    }

    private fun checkCompareVersionEquals(a: String, b: String) {
        assertEquals(0, DataUtil.compareVersion(a, b))
    }
}

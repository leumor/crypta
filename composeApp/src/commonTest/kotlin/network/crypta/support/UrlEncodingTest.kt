package network.crypta.support

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class UrlEncodingTest {

    companion object {
        val prtblAscii = UtfUtils.PRINTABLE_ASCII.concatToString()
        val stressedUTF8Chars = UtfUtils.STRESSED_UTF.concatToString()
        val allChars = UtfUtils.ALL_CHARACTERS.concatToString()
        val allCharsExceptNull = allChars.replace("\u0000", "")
    }

    private fun areCorrectlyEncodedDecoded(toEncode: Array<String>, withLetters: Boolean): Boolean {
        val encoded = toEncode.map { urlEncode(it, withLetters) }
        for (i in toEncode.indices) {
            val orig = toEncode[i]
            val decoded = urlDecode(encoded[i], withLetters)
            if (orig != decoded) return false
        }
        return true
    }

    @Test
    fun testEncodeDecodeString_allChars() {
        assertTrue(areCorrectlyEncodedDecoded(arrayOf(allCharsExceptNull), true))
        assertTrue(areCorrectlyEncodedDecoded(arrayOf(allCharsExceptNull), false))
    }

    @Test
    fun testEncodeDecodeString_notSafeBaseChars() {
        val toEncode = arrayOf(
            SAFE_URL_CHARACTERS,
            prtblAscii,
            "%%%",
            ""
        )
        assertTrue(areCorrectlyEncodedDecoded(toEncode, true))
        assertTrue(areCorrectlyEncodedDecoded(toEncode, false))
    }

    @Test
    fun testEncodeDecodeString_notSafeAdvChars() {
        val toEncode = arrayOf(stressedUTF8Chars)
        assertTrue(areCorrectlyEncodedDecoded(toEncode, true))
        assertTrue(areCorrectlyEncodedDecoded(toEncode, false))
    }

    @Test
    fun testEncodeForced() {
        for (c in SAFE_URL_CHARACTERS) {
            val str = c.toString()
            val expected = "%" + str.encodeToByteArray()
                .joinToString("") { ((it.toInt() and 0xFF).toString(16)).padStart(2, '0') }
            assertEquals(expected, urlEncode(str, str, false))
            assertEquals(expected, urlEncode(str, str, true))
        }
    }

    private fun isDecodeRaisingEncodedException(toDecode: String, tolerant: Boolean): Boolean {
        return try {
            urlDecode(toDecode, tolerant)
            false
        } catch (e: URLEncodedFormatException) {
            true
        }
    }

    @Test
    fun testDecodeWrongString() {
        assertTrue(isDecodeRaisingEncodedException("%00", false))
    }

    @Test
    fun testDecodeWrongHex() {
        val toDecode = "123456789abcde" + prtblAscii + stressedUTF8Chars
        for (i in toDecode.indices) {
            assertTrue(isDecodeRaisingEncodedException("%" + toDecode[i], false))
        }
    }

    @Test
    fun testTolerantDecoding() {
        val toDecode = "%%%"
        assertEquals(toDecode, urlDecode(toDecode, true))
    }
}

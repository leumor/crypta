package network.crypta.support

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class Base64Test {
    @Test
    fun encodeDecodeRoundTrip() {
        val data = byteArrayOf(1, 2, 3, 4)
        val encoded = Base64.encode(data)
        assertContentEquals(data, Base64.decode(encoded))
    }

    @Test
    fun extensionRoundTrip() {
        val data = byteArrayOf(5, 6, 7)
        val encoded = data.encodeBase64()
        assertEquals(Base64.encode(data), encoded)
        assertContentEquals(data, encoded.decodeBase64())
    }

    @Test
    fun utf8Helpers() {
        val str = "Hello \uD83C\uDF0D"
        val encoded = Base64.encodeUTF8(str)
        assertEquals(str, Base64.decodeUTF8(encoded))
        assertEquals(str, str.encodeUTF8Base64().decodeUTF8Base64())
    }

    @Test
    fun freenetEncodingDefaultNoPadding() {
        val data = "AB".encodeToByteArray()
        val encoded = Base64.encodeFreenet(data)
        assertEquals("QUI", encoded)
        assertContentEquals(data, Base64.decodeFreenet(encoded))
        // extension
        val extEncoded = data.encodeFreenetBase64()
        assertEquals(encoded, extEncoded)
        assertContentEquals(data, extEncoded.decodeFreenetBase64())
    }

    @Test
    fun freenetEncodingWithPadding() {
        val data = byteArrayOf(0xFF.toByte())
        val encoded = Base64.encodeFreenet(data, padded = true)
        assertEquals("_w==", encoded)
        assertContentEquals(data, Base64.decodeFreenet(encoded))
        // extension
        val extEncoded = data.encodeFreenetBase64(padded = true)
        assertEquals(encoded, extEncoded)
        assertContentEquals(data, extEncoded.decodeFreenetBase64())
    }
}

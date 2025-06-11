package network.crypta.util

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class Base64FreenetTest {
    @Test
    fun testEncodingDefaultNoPadding() {
        val data = "AB".encodeToByteArray()
        val encoded = data.encodeFreenetBase64()
        assertEquals("QUI", encoded)
        val decoded = encoded.decodeFreenetBase64()
        assertContentEquals(data, decoded)
    }

    @Test
    fun testEncodingWithPadding() {
        val data = byteArrayOf(0xFF.toByte())
        val encoded = data.encodeFreenetBase64(padded = true)
        assertEquals("_w==", encoded)
        val decoded = encoded.decodeFreenetBase64()
        assertContentEquals(data, decoded)
    }
}

package network.crypta.entry

import network.crypta.crypto.SECRET_KEY_SIZE
import network.crypta.crypto.SecretKey
import network.crypta.crypto.toBase64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class UriTest {
    @Test
    fun testRoundTrip() {
        val routingKey = RoutingKey(ByteArray(ROUTING_KEY_SIZE) { it.toByte() })
        val sharedKey = SecretKey(ByteArray(SECRET_KEY_SIZE) { (it + 1).toByte() })
        val extra = byteArrayOf(1, 2, 3)
        val uri = Uri(KeyType.CHK, Uri.Keys(routingKey, sharedKey, extra), listOf("dir", "file"))
        val text = uri.toString()
        val parsed = Uri(text)
        assertEquals(text, parsed.toString())
        assertEquals(uri.uriType, parsed.uriType)
        assertEquals(uri.metaStrings, parsed.metaStrings)
        assertEquals(true, uri.keys.routingKey!!.bytes.contentEquals(parsed.keys.routingKey!!.bytes))
        assertEquals(true, uri.keys.sharedKey!!.bytes.contentEquals(parsed.keys.sharedKey!!.bytes))
        assertEquals(uri.keys.extra, parsed.keys.extra)
    }

    @Test
    fun testParseNoKeys() {
        val uri = Uri("KSK@keyword")
        assertEquals(KeyType.KSK, uri.uriType)
        assertNull(uri.keys.routingKey)
        assertNull(uri.keys.sharedKey)
        assertEquals(listOf("keyword"), uri.metaStrings)
    }

    @Test
    fun testUrlDecoding() {
        val routingKey = RoutingKey(ByteArray(ROUTING_KEY_SIZE))
        val sharedKey = SecretKey(ByteArray(SECRET_KEY_SIZE))
        val rk = routingKey.toBase64()
        val sk = sharedKey.toBase64()
        val encoded = "SSK@${rk},${sk},AAAA/dir%20name/file.txt"
        val uri = Uri(encoded)
        assertEquals("dir%20name", uri.metaStrings[0])
        assertEquals("file.txt", uri.metaStrings[1])
        val expected = "SSK@${rk},${sk},AAAA/dir%2520name/file.txt"
        assertEquals(expected, uri.toLongString(false, true))
    }

    @Test
    fun testEmptySegment() {
        val routingKey = RoutingKey(ByteArray(ROUTING_KEY_SIZE))
        val sharedKey = SecretKey(ByteArray(SECRET_KEY_SIZE))
        val uri = Uri(KeyType.SSK, routingKey, sharedKey, byteArrayOf(), listOf("", "foo"))
        val text = uri.toString()
        val parsed = Uri(text)
        assertEquals(listOf("", "foo"), parsed.metaStrings)
    }
}

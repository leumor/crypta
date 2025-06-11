package network.crypta.entry.key

import network.crypta.crypto.CryptoAlgorithm
import network.crypta.crypto.Hash
import network.crypta.crypto.HashAlgorithm
import network.crypta.crypto.SecretKey
import network.crypta.entry.KeyType
import network.crypta.entry.RoutingKey
import network.crypta.entry.Uri
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class AccessKeyTest {
    @Test
    fun testFromUri() {
        val pubBytes = ByteArray(32) { (it + 1).toByte() }
        val routingKey = RoutingKey(Hash.digest(HashAlgorithm.SHA256, pubBytes))
        val sharedKey = SecretKey(ByteArray(32) { (it + 2).toByte() })
        val extra = byteArrayOf(1, 0, CryptoAlgorithm.AES_PCFB_256_SHA256.value.toByte(), 0, 1)
        val uri = Uri(KeyType.USK, Uri.Keys(routingKey, sharedKey, extra), listOf("site", "5"))

        val usk = Usk.fromUri(uri)
        assertEquals("site", usk.docName)
        assertEquals(5L, usk.suggestedEdition)
        assertContentEquals(routingKey.bytes, usk.routingKey.bytes)
    }

    @Test
    fun testInsertableFromUri() {
        val privBytes = ByteArray(32)
        privBytes[31] = 1
        val sharedKey = SecretKey(ByteArray(32) { (it + 3).toByte() })
        val extra = byteArrayOf(1, 1, CryptoAlgorithm.AES_PCFB_256_SHA256.value.toByte(), 0, 1)
        val uri =
            Uri(KeyType.USK, Uri.Keys(RoutingKey(privBytes), sharedKey, extra), listOf("site", "7"))

        val iUsk = InsertableUsk.fromUri(uri)
        assertEquals("site", iUsk.docName)
        assertEquals(7L, iUsk.suggestedEdition)
        assertEquals(com.ionspin.kotlin.bignum.integer.BigInteger.ONE, iUsk.privateKey.x)
    }
}

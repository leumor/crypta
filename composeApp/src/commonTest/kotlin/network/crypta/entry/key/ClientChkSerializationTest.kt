package network.crypta.entry.key

import network.crypta.crypto.CryptoAlgorithm
import network.crypta.crypto.SecretKey
import network.crypta.entry.RoutingKey
import network.crypta.entry.ROUTING_KEY_SIZE
import network.crypta.crypto.SECRET_KEY_SIZE
import network.crypta.support.network.codec.ClientChkCodec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class ClientChkSerializationTest {
    @Test
    fun roundTrip() {
        val routingKey = RoutingKey(ByteArray(ROUTING_KEY_SIZE) { it.toByte() })
        val sharedKey = SecretKey(ByteArray(SECRET_KEY_SIZE) { (it + 1).toByte() })
        val chk = ClientChk(
            routingKey,
            sharedKey,
            CryptoAlgorithm.AES_CTR_256_SHA256,
            mutableListOf(),
            isControlDocument = true,
            compressionAlgorithm = CompressionAlgorithm.GZIP
        )

        val encoded = ClientChkCodec.serialize(chk)
        val extraExpected = ByteArray(EXTRA_LENGTH).also {
            it[0] = (chk.cryptoAlgorithm.value shr 8).toByte()
            it[1] = chk.cryptoAlgorithm.value.toByte()
            it[2] = 2.toByte()
            it[3] = (chk.compressionAlgorithm.value shr 8).toByte()
            it[4] = chk.compressionAlgorithm.value.toByte()
        }
        val expected = extraExpected + routingKey.bytes + sharedKey.bytes
        assertContentEquals(expected, encoded)

        val decoded = ClientChkCodec.deserialize(encoded)
        assertEquals(chk.cryptoAlgorithm, decoded.cryptoAlgorithm)
        assertEquals(chk.isControlDocument, decoded.isControlDocument)
        assertEquals(chk.compressionAlgorithm, decoded.compressionAlgorithm)
        assertContentEquals(chk.routingKey.bytes, decoded.routingKey.bytes)
        assertContentEquals(chk.sharedKey.bytes, decoded.sharedKey.bytes)
    }
}

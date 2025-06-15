package network.crypta.network

import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable
import kotlinx.serialization.serializer
import network.crypta.crypto.CryptoAlgorithm
import network.crypta.crypto.SECRET_KEY_SIZE
import network.crypta.crypto.SecretKey
import network.crypta.entry.ROUTING_KEY_SIZE
import network.crypta.entry.RoutingKey
import network.crypta.entry.key.ClientChk
import network.crypta.entry.key.CompressionAlgorithm
import network.crypta.support.BitArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class MessageSerializerTest {
    @Serializable
    data class WithChk(
        @Contextual val chk: ClientChk,
        val label: String,
        val id: Int,
    )

    @Test
    fun clientChkRoundTrip() {
        val chk = ClientChk(
            RoutingKey(ByteArray(ROUTING_KEY_SIZE) { it.toByte() }),
            SecretKey(ByteArray(SECRET_KEY_SIZE) { (it + 2).toByte() }),
            CryptoAlgorithm.AES_CTR_256_SHA256,
            mutableListOf("meta"),
            isControlDocument = true,
            compressionAlgorithm = CompressionAlgorithm.GZIP,
        )
        val wrapper = WithChk(chk, "data", 7)

        val bytes = encode(wrapper)

        val expected = encode(ClientChkSerializer, chk) +
                encode(serializer<String>(), wrapper.label) +
                encode(serializer<Int>(), wrapper.id)
        assertContentEquals(expected, bytes)

        val decoded = decode<WithChk>(bytes)
        assertEquals(wrapper.label, decoded.label)
        assertEquals(wrapper.id, decoded.id)
        assertEquals(chk.cryptoAlgorithm, decoded.chk.cryptoAlgorithm)
        assertEquals(chk.isControlDocument, decoded.chk.isControlDocument)
        assertEquals(chk.compressionAlgorithm, decoded.chk.compressionAlgorithm)
        assertContentEquals(chk.routingKey.bytes, decoded.chk.routingKey.bytes)
        assertContentEquals(chk.sharedKey.bytes, decoded.chk.sharedKey.bytes)
        assertEquals(emptyList(), decoded.chk.metaStrings)
    }

    @Test
    fun bitArrayRoundTrip() {
        val arr = BitArray(10)
        arr.setBit(0, true)
        arr.setBit(9, true)

        val bytes = encode(BitArraySerializer, arr)
        val expected = ByteArray(4 + BitArray.toByteSize(arr.getSize()))
        expected[0] = (arr.getSize() ushr 24).toByte()
        expected[1] = (arr.getSize() ushr 16).toByte()
        expected[2] = (arr.getSize() ushr 8).toByte()
        expected[3] = arr.getSize().toByte()
        arr.toByteArray().copyInto(expected, 4)
        assertContentEquals(expected, bytes)

        val decoded = decode(BitArraySerializer, bytes)
        assertEquals(arr, decoded)
    }

    @Test
    fun emptyBitArray() {
        val arr = BitArray(0)
        val bytes = encode(BitArraySerializer, arr)
        assertContentEquals(byteArrayOf(0, 0, 0, 0), bytes)
        val decoded = decode(BitArraySerializer, bytes)
        assertEquals(arr, decoded)
    }
}


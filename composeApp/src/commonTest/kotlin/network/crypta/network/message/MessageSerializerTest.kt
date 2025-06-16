package network.crypta.network.message

import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable
import kotlinx.serialization.serializer
import network.crypta.crypto.CryptoAlgorithm
import network.crypta.entry.ROUTING_KEY_SIZE
import network.crypta.entry.RoutingKey
import network.crypta.entry.key.NodeChk
import network.crypta.entry.key.NodeSsk
import network.crypta.support.BitArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class MessageSerializerTest {

    @Serializable
    data class WithNodeChk(
        @Contextual val chk: NodeChk,
        val label: String,
        val id: Int,
    )

    @Serializable
    data class WithNodeSsk(
        @Contextual val ssk: NodeSsk,
        val label: String,
        val id: Int,
    )

    @Test
    fun nodeChkRoundTrip() {
        val chk = NodeChk(
            RoutingKey(ByteArray(ROUTING_KEY_SIZE) { it.toByte() }),
            CryptoAlgorithm.AES_PCFB_256_SHA256,
        )
        val wrapper = WithNodeChk(chk, "data", 7)

        val bytes = encode(wrapper)

        val expected = encode(NodeChkSerializer, chk) +
                encode(serializer<String>(), wrapper.label) +
                encode(serializer<Int>(), wrapper.id)
        assertContentEquals(expected, bytes)

        val decoded = decode<WithNodeChk>(bytes)
        assertEquals(wrapper.label, decoded.label)
        assertEquals(wrapper.id, decoded.id)
        assertEquals(chk.cryptoAlgorithm, decoded.chk.cryptoAlgorithm)
        assertContentEquals(chk.routingKey.bytes, decoded.chk.routingKey.bytes)
    }

    @Test
    fun nodeSskRoundTrip() {
        val ssk = NodeSsk(
            RoutingKey(ByteArray(ROUTING_KEY_SIZE) { (it + 1).toByte() }),
            CryptoAlgorithm.AES_PCFB_256_SHA256,
            ByteArray(NodeSsk.EH_DOC_NAME_SIZE) { it.toByte() },
        )
        val wrapper = WithNodeSsk(ssk, "info", 8)

        val bytes = encode(wrapper)

        val expected = encode(NodeSskSerializer, ssk) +
                encode(serializer<String>(), wrapper.label) +
                encode(serializer<Int>(), wrapper.id)
        assertContentEquals(expected, bytes)

        val decoded = decode<WithNodeSsk>(bytes)
        assertEquals(wrapper.label, decoded.label)
        assertEquals(wrapper.id, decoded.id)
        assertEquals(ssk.cryptoAlgorithm, decoded.ssk.cryptoAlgorithm)
        assertContentEquals(ssk.clientRoutingKey.bytes, decoded.ssk.clientRoutingKey.bytes)
        assertContentEquals(ssk.ehDocName, decoded.ssk.ehDocName)
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


package network.crypta.network

import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.DoubleArraySerializer
import kotlinx.serialization.serializer
import network.crypta.crypto.CryptoAlgorithm
import network.crypta.crypto.SECRET_KEY_SIZE
import network.crypta.crypto.SecretKey
import network.crypta.entry.ROUTING_KEY_SIZE
import network.crypta.entry.RoutingKey
import network.crypta.entry.key.ClientChk
import network.crypta.entry.key.CompressionAlgorithm
import kotlin.math.E
import kotlin.math.PI
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class MessageSerializationCommonTest {
    @Serializable
    data class Sample(
        val flag: Boolean,
        val number: Int,
        val text: String,
        val numbers: List<Int>,
        val doubles: DoubleArray,
        val floats: FloatArray
    )

    @Test
    fun roundTrip() {
        val value = Sample(
            true,
            42,
            "hello",
            listOf(1, 2, 3),
            doubleArrayOf(1.5, 2.5),
            floatArrayOf(1f, 2f)
        )
        val bytes = encode(value)
        val decoded = decode<Sample>(bytes)
        assertEquals(value.flag, decoded.flag)
        assertEquals(value.number, decoded.number)
        assertEquals(value.text, decoded.text)
        assertEquals(value.numbers, decoded.numbers)
        assertContentEquals(value.doubles, decoded.doubles)
        assertContentEquals(value.floats, decoded.floats)
    }

    @Serializable
    data class AllTypes(
        val bool: Boolean,
        val byteVal: Byte,
        val shortVal: Short,
        val intVal: Int,
        val longVal: Long,
        val doubleVal: Double,
        val floatVal: Float,
        val bytes: ByteArray,
        val text: String,
        val doubles: DoubleArray,
        val floats: FloatArray
    )

    @Test
    fun readWriteAllTypesRoundTrip() {
        val value = AllTypes(
            true,
            9,
            0xDE.toShort(),
            1_234_567,
            123_467_890_123L,
            E,
            123.4567f,
            byteArrayOf(1, 2, 3, 4),
            "testing string",
            doubleArrayOf(PI, 0.1234),
            floatArrayOf(2345.678f, 8901.234f)
        )

        val bytes = encode(value)
        val decoded = decode<AllTypes>(bytes)
        assertEquals(value.bool, decoded.bool)
        assertEquals(value.byteVal, decoded.byteVal)
        assertEquals(value.shortVal, decoded.shortVal)
        assertEquals(value.intVal, decoded.intVal)
        assertEquals(value.longVal, decoded.longVal)
        assertEquals(value.doubleVal, decoded.doubleVal)
        assertEquals(value.floatVal, decoded.floatVal)
        assertContentEquals(value.bytes, decoded.bytes)
        assertEquals(value.text, decoded.text)
        assertContentEquals(value.doubles, decoded.doubles)
        assertContentEquals(value.floats, decoded.floats)
    }

    @Serializable
    data class WithChk(
        @Contextual
        val chk: ClientChk,
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
    fun doubleArrayEdgeCasesRoundTrip() {
        val cases = arrayOf(DoubleArray(0), DoubleArray(128), DoubleArray(255))
        var v = 0.0
        for (case in cases) {
            for (i in case.indices) {
                v += 5.0
                case[i] = v
            }
            val bytes = encode(DoubleArraySerializer(), case)
            assertEquals(1 + 8 * case.size, bytes.size)
            val decoded = decode(DoubleArraySerializer(), bytes)
            assertContentEquals(case, decoded)
        }
    }

    @Test
    fun tooLongDoubleArray() {
        val arr = DoubleArray(256)
        assertFailsWith<IllegalArgumentException> {
            encode(DoubleArraySerializer(), arr)
        }
    }
}

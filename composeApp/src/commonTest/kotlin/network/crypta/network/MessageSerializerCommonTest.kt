package network.crypta.network

import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.DoubleArraySerializer
import kotlin.math.E
import kotlin.math.PI
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class MessageSerializerCommonTest {
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
        assertEquals(value.text, decoded.text)
        assertContentEquals(value.doubles, decoded.doubles)
        assertContentEquals(value.floats, decoded.floats)
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

package network.crypta.network

import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.DoubleArraySerializer
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import kotlin.math.PI
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class MessageSerializerJvmTest {
    @Serializable
    data class Simple(val flag: Boolean, val number: Int, val text: String)

    @Test
    fun compatibleWithDataStreams() {
        val value = Simple(true, 123, "hey")
        val custom = encode(value)

        val baos = ByteArrayOutputStream()
        DataOutputStream(baos).use { out ->
            out.writeBoolean(value.flag)
            out.writeInt(value.number)
            out.writeInt(value.text.length)
            for (ch in value.text) out.writeChar(ch.code)
        }
        val expected = baos.toByteArray()
        assertContentEquals(expected, custom)

        val read = decode<Simple>(expected)
        assertEquals(value, read)

        DataInputStream(ByteArrayInputStream(custom)).use { input ->
            val f = input.readBoolean()
            val n = input.readInt()
            val len = input.readInt()
            val sb = StringBuilder()
            repeat(len) { sb.append(input.readChar()) }
            assertEquals(value, Simple(f, n, sb.toString()))
        }
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
    fun readWriteAllTypes() {
        val value = AllTypes(
            true,
            9,
            0xDE.toShort(),
            1_234_567,
            123_467_890_123L,
            kotlin.math.E,
            123.4567f,
            "testing string",
            doubleArrayOf(PI, 0.1234),
            floatArrayOf(2345.678f, 8901.234f)
        )

        val encoded = encode(value)

        val baos = ByteArrayOutputStream()
        DataOutputStream(baos).use { out ->
            out.writeBoolean(value.bool)
            out.writeByte(value.byteVal.toInt())
            out.writeShort(value.shortVal.toInt())
            out.writeInt(value.intVal)
            out.writeLong(value.longVal)
            out.writeDouble(value.doubleVal)
            out.writeFloat(value.floatVal)
            out.writeInt(value.text.length)
            for (ch in value.text) out.writeChar(ch.code)
            out.writeByte(value.doubles.size)
            for (d in value.doubles) out.writeDouble(d)
            out.writeShort(value.floats.size)
            for (f in value.floats) out.writeFloat(f)
        }
        val expected = baos.toByteArray()
        assertContentEquals(expected, encoded)

        val decoded = decode<AllTypes>(encoded)
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

        DataInputStream(ByteArrayInputStream(encoded)).use { input ->
            assertEquals(value.bool, input.readBoolean())
            assertEquals(value.byteVal, input.readByte())
            assertEquals(value.shortVal, input.readShort())
            assertEquals(value.intVal, input.readInt())
            assertEquals(value.longVal, input.readLong())
            assertEquals(value.doubleVal, input.readDouble(), 0.0)
            assertEquals(value.floatVal, input.readFloat(), 0.0f)
            val len = input.readInt()
            val sb = StringBuilder()
            repeat(len) { sb.append(input.readChar()) }
            assertEquals(value.text, sb.toString())
            val dblSize = input.readByte().toInt() and 0xFF
            val dArr = DoubleArray(dblSize) { input.readDouble() }
            assertContentEquals(value.doubles, dArr)
            val fSize = input.readShort().toInt() and 0xFFFF
            val fArr = FloatArray(fSize) { input.readFloat() }
            assertContentEquals(value.floats, fArr)
        }
    }

    @Test
    fun doubleArrayEdgeCases() {
        val cases = arrayOf(DoubleArray(0), DoubleArray(128), DoubleArray(255))
        var v = 0.0
        for (case in cases) {
            for (i in case.indices) {
                v += 5.0
                case[i] = v
            }
            val bytes = encode(DoubleArraySerializer(), case)
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                val size = input.readByte().toInt() and 0xFF
                assertEquals(case.size, size)
                val arr = DoubleArray(size) { input.readDouble() }
                assertContentEquals(case, arr)
            }
        }
    }
}

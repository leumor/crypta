package network.crypta.support.network

import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.DoubleArraySerializer
import kotlinx.io.Buffer
import kotlin.math.E
import kotlin.math.PI
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import network.crypta.entry.key.ClientChk
import network.crypta.crypto.SecretKey
import network.crypta.entry.RoutingKey
import network.crypta.entry.ROUTING_KEY_SIZE
import network.crypta.crypto.SECRET_KEY_SIZE
import network.crypta.crypto.CryptoAlgorithm
import network.crypta.entry.key.CompressionAlgorithm

private fun Buffer.toByteArray(): ByteArray {
    val result = ByteArray(size.toInt())
    readAtMostTo(result, 0, result.size)
    return result
}

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

    private fun expectedBytes(value: Sample): ByteArray {
        val buf = Buffer()
        buf.writeByte((if (value.flag) 1 else 0).toByte())
        buf.writeInt(value.number)
        buf.writeInt(value.text.length)
        for (ch in value.text) buf.writeShort(ch.code.toShort())
        buf.writeInt(value.numbers.size)
        for (n in value.numbers) buf.writeInt(n)
        buf.writeByte(value.doubles.size.toByte())
        for (d in value.doubles) buf.writeLong(d.toBits())
        buf.writeShort(value.floats.size.toShort())
        for (f in value.floats) buf.writeInt(f.toBits())
        return buf.toByteArray()
    }

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
        assertContentEquals(expectedBytes(value), bytes)
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

    private fun expectedBytes(value: AllTypes): ByteArray {
        val buf = Buffer()
        buf.writeByte((if (value.bool) 1 else 0).toByte())
        buf.writeByte(value.byteVal)
        buf.writeShort(value.shortVal)
        buf.writeInt(value.intVal)
        buf.writeLong(value.longVal)
        buf.writeLong(value.doubleVal.toBits())
        buf.writeInt(value.floatVal.toBits())
        buf.writeInt(value.bytes.size)
        buf.write(value.bytes)
        buf.writeInt(value.text.length)
        for (ch in value.text) buf.writeShort(ch.code.toShort())
        buf.writeByte(value.doubles.size.toByte())
        for (d in value.doubles) buf.writeLong(d.toBits())
        buf.writeShort(value.floats.size.toShort())
        for (f in value.floats) buf.writeInt(f.toBits())
        return buf.toByteArray()
    }

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
        assertContentEquals(expectedBytes(value), bytes)
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
        val chk: ClientChk,
        val label: String,
    )

    private fun expectedBytes(value: WithChk): ByteArray {
        val buf = Buffer()
        // ClientChk fields
        buf.writeInt(value.chk.routingKey.bytes.size)
        buf.write(value.chk.routingKey.bytes)
        buf.writeInt(value.chk.sharedKey.bytes.size)
        buf.write(value.chk.sharedKey.bytes)
        buf.writeInt(value.chk.cryptoAlgorithm.ordinal)
        buf.writeInt(value.chk.metaStrings.size)
        for (s in value.chk.metaStrings) {
            buf.writeInt(s.length)
            for (ch in s) buf.writeShort(ch.code.toShort())
        }
        buf.writeByte((if (value.chk.isControlDocument) 1 else 0).toByte())
        buf.writeInt(value.chk.compressionAlgorithm.ordinal)
        // label
        buf.writeInt(value.label.length)
        for (ch in value.label) buf.writeShort(ch.code.toShort())
        return buf.toByteArray()
    }

    @Test
    fun clientChkRoundTrip() {
        val chk = ClientChk(
            RoutingKey(ByteArray(ROUTING_KEY_SIZE) { it.toByte() }),
            SecretKey(ByteArray(SECRET_KEY_SIZE) { (it + 2).toByte() }),
            CryptoAlgorithm.AES_CTR_256_SHA256,
            mutableListOf("meta"),
            isControlDocument = false,
            compressionAlgorithm = CompressionAlgorithm.GZIP,
        )
        val wrapper = WithChk(chk, "data")
        val bytes = encode(wrapper)
        assertContentEquals(expectedBytes(wrapper), bytes)
        val decoded = decode<WithChk>(bytes)
        assertEquals(wrapper.label, decoded.label)
        assertEquals(chk.cryptoAlgorithm, decoded.chk.cryptoAlgorithm)
        assertEquals(chk.isControlDocument, decoded.chk.isControlDocument)
        assertEquals(chk.compressionAlgorithm, decoded.chk.compressionAlgorithm)
        assertContentEquals(chk.routingKey.bytes, decoded.chk.routingKey.bytes)
        assertContentEquals(chk.sharedKey.bytes, decoded.chk.sharedKey.bytes)
        assertEquals(chk.metaStrings, decoded.chk.metaStrings)
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
            val expectedBuf = Buffer()
            expectedBuf.writeByte(case.size.toByte())
            for (d in case) expectedBuf.writeLong(d.toBits())
            val expected = expectedBuf.toByteArray()
            assertContentEquals(expected, bytes)
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

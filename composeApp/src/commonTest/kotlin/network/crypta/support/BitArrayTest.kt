package network.crypta.support

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class BitArrayTest {
    private val sampleBitsNumber = 10
    private val oneByteBits = 8

    private fun createAllEqualsBitArray(arraySize: Int, value: Boolean): BitArray {
        val ba = BitArray(arraySize)
        for (i in 0 until ba.getSize()) ba.setBit(i, value)
        return ba
    }

    private fun createRepeatedString(size: Int, value: String): String {
        val sb = StringBuilder()
        repeat(size) { sb.append(value) }
        return sb.toString()
    }

    @Test
    fun bitArrayInt() {
        val ba = BitArray(sampleBitsNumber)
        for (i in 0 until sampleBitsNumber) {
            assertFalse(ba.bitAt(i))
        }
        assertEquals(sampleBitsNumber, ba.getSize())
    }

    @Test
    fun toStringAllEquals() {
        var ba = createAllEqualsBitArray(sampleBitsNumber, true)
        var expected = createRepeatedString(sampleBitsNumber, "1")
        assertEquals(expected, ba.toString())

        ba = createAllEqualsBitArray(sampleBitsNumber, false)
        expected = createRepeatedString(sampleBitsNumber, "0")
        assertEquals(expected, ba.toString())
    }

    @Test
    fun toStringEmpty() {
        val ba = BitArray(0)
        assertEquals(0, ba.toString().length)
    }

    @Test
    fun setBitOutOfBounds() {
        val ba = BitArray(sampleBitsNumber)
        assertFailsWith<IndexOutOfBoundsException> {
            ba.setBit(sampleBitsNumber, true)
        }
    }

    @Test
    fun setAndGetBit() {
        val ba = BitArray(sampleBitsNumber)
        for (i in 0 until ba.getSize() step 2) ba.setBit(i, true)
        for (i in 0 until ba.getSize() step 2) assertTrue(ba.bitAt(i))
        for (i in 1 until ba.getSize() step 2) assertFalse(ba.bitAt(i))
    }

    @Test
    fun unsignedByteToInt() {
        for (i in 0 until 256) {
            val b = i.toByte()
            assertEquals(i, BitArray.unsignedByteToInt(b))
        }
    }

    @Test
    fun getSize() {
        var ba = BitArray(0)
        assertEquals(0, ba.getSize())
        ba = createAllEqualsBitArray(sampleBitsNumber, true)
        assertEquals(sampleBitsNumber, ba.getSize())
    }

    @Test
    fun setAllOnes() {
        val ba = createAllEqualsBitArray(sampleBitsNumber, true)
        val verify = BitArray(sampleBitsNumber)
        verify.setAllOnes()
        assertEquals(ba, verify)
    }

    @Test
    fun firstOne() {
        val ba = BitArray(oneByteBits)
        for (i in 0 until oneByteBits) {
            ba.setSize(oneByteBits)
            for (j in 0 until oneByteBits) ba.setBit(j, false)
            ba.setBit(i, true)
            assertEquals(i, ba.firstOne())
        }

        ba.setAllOnes()
        for (i in 0 until oneByteBits - 1) {
            ba.setBit(i, false)
            assertEquals(i + 1, ba.firstOne())
        }
        ba.setBit(oneByteBits - 1, false)
        assertEquals(-1, ba.firstOne())
    }

    @Test
    fun lastOne() {
        val ba = BitArray(16)
        ba.setAllOnes()
        for (i in 15 downTo 0) {
            assertEquals(i, ba.lastOne(Int.MAX_VALUE))
            assertEquals(i, ba.lastOne(i + 1))
            assertEquals(i, ba.lastOne(i + 8))
            ba.setBit(i, false)
        }
        assertEquals(-1, ba.lastOne(Int.MAX_VALUE))
        assertEquals(-1, ba.lastOne(0))
    }

    @Test
    fun shrinkGrow() {
        val ba = BitArray(16)
        ba.setAllOnes()
        ba.setSize(9)
        ba.setSize(16)
        for (i in 9 until 16) assertFalse(ba.bitAt(i))
        for (i in 0 until 9) assertTrue(ba.bitAt(i))
    }
}

package network.crypta.support

/**
 * A simple mutable bit array implementation.
 *
 * This class stores bits in a [ByteArray] and provides utility
 * functions similar to Java's `BitSet` but is portable across
 * Kotlin targets.
 */
class BitArray {
    private var size: Int
    private var bits: ByteArray

    /** Create a bit array initialized with the given raw bit bytes. */
    constructor(data: ByteArray) {
        bits = data.copyOf()
        size = data.size * 8
        trimToSize()
    }

    /** Create a copy of another [BitArray]. */
    constructor(src: BitArray) {
        size = src.size
        bits = src.bits.copyOf()
    }

    /** Create a bit array with the specified number of bits. */
    constructor(size: Int) {
        require(size >= 0) { "Size must be non-negative" }
        this.size = size
        bits = ByteArray(toByteSize(size))
    }

    /** Number of bits in this array. */
    fun getSize(): Int = size

    /** Create a new copy of this bit array. */
    fun copy(): BitArray = BitArray(this)

    /** Set the bit at [pos] to [value]. */
    fun setBit(pos: Int, value: Boolean) {
        checkPos(pos)
        val index = pos ushr 3
        val mask = (1 shl (pos and 7))
        if (value) {
            bits[index] = (bits[index].toInt() or mask).toByte()
        } else {
            bits[index] = (bits[index].toInt() and mask.inv()).toByte()
        }
    }

    /** Return the value of the bit at [pos]. */
    fun bitAt(pos: Int): Boolean {
        checkPos(pos)
        val index = pos ushr 3
        val mask = 1 shl (pos and 7)
        return (bits[index].toInt() and mask) != 0
    }

    /** Set all bits in the array to 1. */
    fun setAllOnes() {
        bits.fill(0xFF.toByte())
        trimToSize()
    }

    /** Return the index of the first set bit at or after [start], or -1 if none. */
    fun firstOne(start: Int = 0): Int {
        for (i in start until size) if (bitAt(i)) return i
        return -1
    }

    /** Return the index of the first zero bit at or after [start], or -1 if none. */
    fun firstZero(start: Int = 0): Int {
        for (i in start until size) if (!bitAt(i)) return i
        return -1
    }

    /** Return the index of the last set bit at or before [start], or -1 if none. */
    fun lastOne(start: Int = size - 1): Int {
        var i = if (start >= size) size - 1 else start
        while (i >= 0) {
            if (bitAt(i)) return i
            i--
        }
        return -1
    }

    /** Change the logical size of this bit array. */
    fun setSize(newSize: Int) {
        require(newSize >= 0) { "Size must be non-negative" }
        size = newSize
        val required = toByteSize(size)
        if (bits.size < required) bits = bits.copyOf(required)
        trimToSize()
    }

    /** Raw byte representation of the bits (least significant bit first). */
    fun toByteArray(): ByteArray = bits.copyOf(getByteSize())

    override fun toString(): String {
        val sb = StringBuilder(size)
        for (i in 0 until size) sb.append(if (bitAt(i)) '1' else '0')
        return sb.toString()
    }

    override fun equals(other: Any?): Boolean {
        if (other !is BitArray) return false
        if (other.size != size) return false
        return toByteArray().contentEquals(other.toByteArray())
    }

    override fun hashCode(): Int = toByteArray().contentHashCode() xor size

    private fun trimToSize() {
        val byteSize = getByteSize()
        if (bits.size > byteSize) bits = bits.copyOf(byteSize)
        val extra = size and 7
        if (extra != 0 && bits.isNotEmpty()) {
            val mask = (1 shl extra) - 1
            bits[byteSize - 1] = (bits[byteSize - 1].toInt() and mask).toByte()
        }
    }

    private fun getByteSize(): Int = toByteSize(size)

    private fun checkPos(pos: Int) {
        if (pos >= size || pos < 0) throw IndexOutOfBoundsException()
    }

    companion object {
        /** Number of bytes required to hold [bitSize] bits. */
        fun toByteSize(bitSize: Int): Int = (bitSize + 7) / 8

        /** Length of the serialized form for the given bit size. */
        fun serializedLength(size: Int): Int = toByteSize(size) + 4

        /** Convert a signed byte value to its unsigned integer representation. */
        fun unsignedByteToInt(b: Byte): Int = b.toInt() and 0xFF

        private fun writeInt(array: ByteArray, offset: Int, value: Int) {
            array[offset] = (value ushr 24).toByte()
            array[offset + 1] = (value ushr 16).toByte()
            array[offset + 2] = (value ushr 8).toByte()
            array[offset + 3] = value.toByte()
        }
    }
}


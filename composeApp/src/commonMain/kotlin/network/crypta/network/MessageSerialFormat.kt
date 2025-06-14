@file:OptIn(ExperimentalSerializationApi::class)

package network.crypta.network

import kotlinx.io.Buffer
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.AbstractEncoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.serializer

/** A multiplatform Crypta network message serializer. */

/** Encode [value] using [serializer] into a new [ByteArray]. */
fun <T> encode(serializer: SerializationStrategy<T>, value: T): ByteArray {
    val buffer = Buffer()
    val encoder = Encoder(buffer)
    encoder.encodeSerializableValue(serializer, value)
    val result = ByteArray(buffer.size.toInt())
    buffer.readAtMostTo(result, 0, result.size)
    return result
}

/** Decode [data] into an object of type [T] using [deserializer]. */
fun <T> decode(deserializer: DeserializationStrategy<T>, data: ByteArray): T {
    val buffer = Buffer()
    buffer.write(data)
    val decoder = Decoder(buffer)
    return decoder.decodeSerializableValue(deserializer)
}

/** Inline reified wrappers for easier invocation. */
inline fun <reified T> encode(value: T): ByteArray =
    encode(serializer(), value)

inline fun <reified T> decode(data: ByteArray): T =
    decode(serializer(), data)

private class Encoder(private val sink: Buffer) : AbstractEncoder() {
    override val serializersModule: SerializersModule = MessageSerialModule

    override fun encodeBoolean(value: Boolean) = sink.writeByte(if (value) 1 else 0)
    override fun encodeByte(value: Byte) = sink.writeByte(value)
    override fun encodeShort(value: Short) = sink.writeShort(value)
    override fun encodeInt(value: Int) = sink.writeInt(value)
    override fun encodeLong(value: Long) = sink.writeLong(value)
    override fun encodeChar(value: Char) = sink.writeShort(value.code.toShort())
    override fun encodeFloat(value: Float) = sink.writeInt(value.toBits())
    override fun encodeDouble(value: Double) = sink.writeLong(value.toBits())
    override fun encodeString(value: String) {
        encodeInt(value.length)
        for (ch in value) encodeChar(ch)
    }

    override fun encodeEnum(enumDescriptor: SerialDescriptor, index: Int) = sink.writeInt(index)

    override fun beginCollection(descriptor: SerialDescriptor, collectionSize: Int) = apply {
        if (descriptor.kind == StructureKind.LIST) {
            sink.writeInt(collectionSize)
        }
    }

    override fun <T> encodeSerializableValue(serializer: SerializationStrategy<T>, value: T) {
        when (serializer.descriptor.serialName) {
            "kotlin.DoubleArray" -> {
                val arr = value as DoubleArray
                require(arr.size <= 255) {
                    "Cannot serialize an array of more than 255 doubles; attempted to serialize ${arr.size}."
                }
                sink.writeByte(arr.size.toByte())
                for (d in arr) encodeDouble(d)
            }

            "kotlin.FloatArray" -> {
                val arr = value as FloatArray
                require(arr.size <= 0xFFFF)
                sink.writeShort(arr.size.toShort())
                for (f in arr) encodeFloat(f)
            }

            "kotlin.ByteArray" -> {
                val arr = value as ByteArray
                sink.writeInt(arr.size)
                sink.write(arr)
            }

            else -> serializer.serialize(this, value)
        }
    }
}

private class Decoder(private val source: Buffer) : AbstractDecoder() {
    override val serializersModule: SerializersModule = MessageSerialModule

    private val indices = ArrayDeque<Int>()
    private val listRemaining = ArrayDeque<Int>()

    override fun decodeBoolean(): Boolean = source.readByte() != 0.toByte()
    override fun decodeByte(): Byte = source.readByte()
    override fun decodeShort(): Short = source.readShort()
    override fun decodeInt(): Int = source.readInt()
    override fun decodeLong(): Long = source.readLong()
    override fun decodeChar(): Char = source.readShort().toInt().toChar()
    override fun decodeFloat(): Float = Float.fromBits(source.readInt())
    override fun decodeDouble(): Double = Double.fromBits(source.readLong())

    override fun decodeString(): String {
        val length = decodeInt()
        val sb = StringBuilder(length)
        repeat(length) { sb.append(decodeChar()) }
        return sb.toString()
    }

    override fun decodeEnum(enumDescriptor: SerialDescriptor): Int = source.readInt()

    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {
        indices.addLast(0)
        if (descriptor.kind == StructureKind.LIST) {
            val size = source.readInt()
            listRemaining.addLast(size)
        }
        return this
    }

    override fun endStructure(descriptor: SerialDescriptor) {
        indices.removeLast()
        if (descriptor.kind == StructureKind.LIST) {
            listRemaining.removeLast()
        }
    }

    override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
        return if (descriptor.kind == StructureKind.LIST) {
            val remaining = listRemaining.removeLast()
            val index = indices.removeLast()
            if (remaining == 0) {
                listRemaining.addLast(remaining)
                indices.addLast(index)
                CompositeDecoder.DECODE_DONE
            } else {
                listRemaining.addLast(remaining - 1)
                indices.addLast(index + 1)
                index
            }
        } else {
            val current = indices.removeLastOrNull() ?: return CompositeDecoder.DECODE_DONE
            if (current == descriptor.elementsCount) {
                indices.addLast(current)
                CompositeDecoder.DECODE_DONE
            } else {
                indices.addLast(current + 1)
                current
            }
        }
    }

    override fun decodeCollectionSize(descriptor: SerialDescriptor): Int {
        return if (descriptor.kind == StructureKind.LIST) listRemaining.last() else super.decodeCollectionSize(
            descriptor
        )
    }

    override fun <T> decodeSerializableValue(deserializer: DeserializationStrategy<T>): T {
        @Suppress("UNCHECKED_CAST")
        return when (deserializer.descriptor.serialName) {
            "kotlin.DoubleArray" -> {
                val size = source.readByte().toInt() and 0xFF
                val arr = DoubleArray(size)
                for (i in 0 until size) arr[i] = decodeDouble()
                arr as T
            }

            "kotlin.FloatArray" -> {
                val size = source.readShort().toInt() and 0xFFFF
                val arr = FloatArray(size)
                for (i in 0 until size) arr[i] = decodeFloat()
                arr as T
            }

            "kotlin.ByteArray" -> {
                val size = source.readInt()
                val arr = ByteArray(size)
                source.readAtMostTo(arr, 0, size)
                arr as T
            }

            else -> deserializer.deserialize(this)
        }
    }
}


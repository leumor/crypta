package network.crypta.support.network

import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.contextual
import kotlinx.serialization.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/** Contract for types that can convert themselves to and from a [ByteArray]. */
interface MessageSerializable<T> {
    fun serialize(value: T): ByteArray
    fun deserialize(bytes: ByteArray): T
}

/** [KSerializer] delegating to a [MessageSerializable] implementation. */
class MessageSerializableSerializer<T>(
    private val delegate: MessageSerializable<T>
) : KSerializer<T> {
    override val descriptor: SerialDescriptor = ByteArraySerializer().descriptor

    override fun serialize(encoder: Encoder, value: T) {
        val bytes = delegate.serialize(value)
        encoder.encodeSerializableValue(ByteArraySerializer(), bytes)
    }

    override fun deserialize(decoder: Decoder): T {
        val bytes = decoder.decodeSerializableValue(ByteArraySerializer())
        return delegate.deserialize(bytes)
    }
}

/**
 * Creates a [MessageSerializable] for type [T] using the compiler generated
 * `serializer<T>()` and [MessageSerialFormat].
 */
inline fun <reified T> messageSerializable(): MessageSerializable<T> {
    val kSerializer = MessageSerialModule.serializer<T>()
    return object : MessageSerializable<T> {
        override fun serialize(value: T): ByteArray = encode(kSerializer, value)
        override fun deserialize(bytes: ByteArray): T = decode(kSerializer, bytes)
    }
}

/** [SerializersModule] registering support for [MessageSerializable] types. */
val MessageSerialModule: SerializersModule = SerializersModule {
    contextual(MessageSerializable::class) { args ->
        @Suppress("UNCHECKED_CAST")
        MessageSerializableSerializer(args[0] as MessageSerializable<Any?>) as KSerializer<Any?>
    }
}

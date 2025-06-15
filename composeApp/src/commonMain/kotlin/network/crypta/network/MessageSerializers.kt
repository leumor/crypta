package network.crypta.network

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.contextual
import network.crypta.crypto.SECRET_KEY_SIZE
import network.crypta.entry.ROUTING_KEY_SIZE
import network.crypta.entry.RoutingKey
import network.crypta.entry.SharedKey
import network.crypta.entry.key.ClientChk
import network.crypta.entry.key.ClientChk.ExtraData
import network.crypta.entry.key.EXTRA_LENGTH
import network.crypta.support.BitArray

/** Serializer for [ClientChk] that encodes it as raw bytes. */
object ClientChkSerializer : KSerializer<ClientChk> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ClientChk", PrimitiveKind.BYTE)

    override fun serialize(encoder: Encoder, value: ClientChk) {
        val extra = ExtraData(
            value.cryptoAlgorithm,
            value.isControlDocument,
            value.compressionAlgorithm
        ).toByteArray()
        val bytes = extra + value.routingKey.bytes + value.sharedKey.bytes
        for (b in bytes) encoder.encodeByte(b)
    }

    override fun deserialize(decoder: Decoder): ClientChk {
        val extra = ByteArray(EXTRA_LENGTH)
        for (i in extra.indices) extra[i] = decoder.decodeByte()
        val routingBytes = ByteArray(ROUTING_KEY_SIZE)
        for (i in routingBytes.indices) routingBytes[i] = decoder.decodeByte()
        val sharedBytes = ByteArray(SECRET_KEY_SIZE)
        for (i in sharedBytes.indices) sharedBytes[i] = decoder.decodeByte()
        val extraData = ExtraData.fromByteArray(extra)
        return ClientChk(
            RoutingKey(routingBytes),
            SharedKey(sharedBytes),
            extraData.cryptoAlgorithm,
            mutableListOf(),
            extraData.isControlDocument,
            extraData.compressionAlgorithm
        )
    }
}

/** Serializer for [BitArray] matching the Java data stream format. */
object BitArraySerializer : KSerializer<BitArray> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("BitArray", PrimitiveKind.BYTE)

    override fun serialize(encoder: Encoder, value: BitArray) {
        encoder.encodeInt(value.getSize())
        val bytes = value.toByteArray()
        for (b in bytes) encoder.encodeByte(b)
    }

    override fun deserialize(decoder: Decoder): BitArray {
        val size = decoder.decodeInt()
        val byteSize = BitArray.toByteSize(size)
        val data = ByteArray(byteSize)
        for (i in 0 until byteSize) data[i] = decoder.decodeByte()
        val result = BitArray(data)
        result.setSize(size)
        return result
    }
}

/** Serializers module registering Crypta-specific serializers. */
val MessageSerialModule: SerializersModule = SerializersModule {
    contextual(ClientChkSerializer)
    contextual(BitArraySerializer)
}

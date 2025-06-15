package network.crypta.network

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.contextual
import network.crypta.crypto.CryptoAlgorithm
import network.crypta.entry.ROUTING_KEY_SIZE
import network.crypta.entry.RoutingKey
import network.crypta.entry.key.NodeChk
import network.crypta.entry.key.NodeSsk
import network.crypta.support.BitArray

/** Serializer for [NodeChk] that encodes it as raw bytes. */
object NodeChkSerializer : KSerializer<NodeChk> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("NodeChk", PrimitiveKind.BYTE)

    override fun serialize(encoder: Encoder, value: NodeChk) {
        encoder.encodeShort(value.getType())
        for (b in value.routingKey.bytes) encoder.encodeByte(b)
    }

    override fun deserialize(decoder: Decoder): NodeChk {
        val type = decoder.decodeShort()
        val routingBytes = ByteArray(ROUTING_KEY_SIZE)
        for (i in routingBytes.indices) routingBytes[i] = decoder.decodeByte()
        require(((type.toInt() shr 8) and 0xFF) == NodeChk.BASE_TYPE.toInt())
        val algorithm = CryptoAlgorithm.fromValue(type.toInt() and 0xFF)
        return NodeChk(RoutingKey(routingBytes), algorithm)
    }
}

/** Serializer for [NodeSsk] that encodes it as raw bytes. */
object NodeSskSerializer : KSerializer<NodeSsk> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("NodeSsk", PrimitiveKind.BYTE)

    override fun serialize(encoder: Encoder, value: NodeSsk) {
        encoder.encodeShort(value.getType())
        for (b in value.ehDocName) encoder.encodeByte(b)
        for (b in value.clientRoutingKey.bytes) encoder.encodeByte(b)
    }

    override fun deserialize(decoder: Decoder): NodeSsk {
        val type = decoder.decodeShort()
        val ehDocName = ByteArray(NodeSsk.EH_DOC_NAME_SIZE)
        for (i in ehDocName.indices) ehDocName[i] = decoder.decodeByte()
        val routingBytes = ByteArray(ROUTING_KEY_SIZE)
        for (i in routingBytes.indices) routingBytes[i] = decoder.decodeByte()
        require(((type.toInt() shr 8) and 0xFF) == NodeSsk.BASE_TYPE.toInt())
        val algorithm = CryptoAlgorithm.fromValue(type.toInt() and 0xFF)
        return NodeSsk(RoutingKey(routingBytes), algorithm, ehDocName)
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
    contextual(NodeChkSerializer)
    contextual(NodeSskSerializer)
    contextual(BitArraySerializer)
}

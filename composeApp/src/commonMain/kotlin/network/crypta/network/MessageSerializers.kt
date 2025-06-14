package network.crypta.network

import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
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
        encoder.encodeSerializableValue(ByteArraySerializer(), bytes)
    }

    override fun deserialize(decoder: Decoder): ClientChk {
        val bytes = decoder.decodeSerializableValue(ByteArraySerializer())
        require(bytes.size >= EXTRA_LENGTH + ROUTING_KEY_SIZE + SECRET_KEY_SIZE) {
            "CHK encoding too short"
        }
        val extra = bytes.copyOfRange(0, EXTRA_LENGTH)
        val routingBytes = bytes.copyOfRange(EXTRA_LENGTH, EXTRA_LENGTH + ROUTING_KEY_SIZE)
        val sharedBytes = bytes.copyOfRange(
            EXTRA_LENGTH + ROUTING_KEY_SIZE,
            EXTRA_LENGTH + ROUTING_KEY_SIZE + SECRET_KEY_SIZE
        )
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

/** Serializers module registering Crypta-specific serializers. */
val MessageSerialModule: SerializersModule = SerializersModule {
    contextual(ClientChkSerializer)
}

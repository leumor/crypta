package network.crypta.support.network.codec

import network.crypta.entry.ROUTING_KEY_SIZE
import network.crypta.crypto.SECRET_KEY_SIZE
import network.crypta.entry.RoutingKey
import network.crypta.entry.SharedKey
import network.crypta.entry.key.EXTRA_LENGTH
import network.crypta.entry.key.ClientChk
import network.crypta.entry.key.ClientChk.ExtraData
import network.crypta.support.network.MessageSerializable

/** Codec responsible for serializing and deserializing [ClientChk] instances. */
object ClientChkCodec : MessageSerializable<ClientChk> {

    override fun serialize(value: ClientChk): ByteArray {
        val extra = ExtraData(
            value.cryptoAlgorithm,
            value.isControlDocument,
            value.compressionAlgorithm
        ).toByteArray()
        return extra + value.routingKey.bytes + value.sharedKey.bytes
    }

    override fun deserialize(bytes: ByteArray): ClientChk {
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

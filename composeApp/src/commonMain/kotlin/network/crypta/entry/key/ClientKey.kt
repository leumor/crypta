package network.crypta.entry.key

import network.crypta.crypto.CryptoAlgorithm
import network.crypta.crypto.DSAPrivateKey
import network.crypta.crypto.DSAPublicKey
import network.crypta.crypto.Hash
import network.crypta.crypto.HashAlgorithm
import network.crypta.crypto.Rijndael256
import network.crypta.entry.RoutingKey
import network.crypta.entry.SharedKey

abstract class ClientKey(
    routingKey: RoutingKey,
    sharedKey: SharedKey?,
    cryptoAlgorithm: CryptoAlgorithm,
    metaStrings: MutableList<String>
) : AccessKey(routingKey, sharedKey, cryptoAlgorithm, metaStrings) {

}

const val EXTRA_LENGTH = 5

class ClientChk(
    routingKey: RoutingKey,
    sharedKey: SharedKey?,
    cryptoAlgorithm: CryptoAlgorithm,
    metaStrings: List<String>,
    val isControlDocument: Boolean,
    val compressionAlgorithm: CompressionAlgorithm
) : ClientKey(routingKey, sharedKey, cryptoAlgorithm, mutableListOf()) {

    private data class ExtraData(
        val cryptoAlgorithm: CryptoAlgorithm,
        val isControlDocument: Boolean,
        val compressionAlgorithm: CompressionAlgorithm,
    ) {
        fun toByteArray(): ByteArray {
            val extra = ByteArray(EXTRA_LENGTH)
            extra[0] = (cryptoAlgorithm.value shr 8).toByte()
            extra[1] = cryptoAlgorithm.value.toByte()
            extra[2] = (if (isControlDocument) 2 else 0).toByte()
            extra[3] = (compressionAlgorithm.value shr 8).toByte()
            extra[4] = compressionAlgorithm.value.toByte()
            return extra

        }

        companion object {
            fun fromByteArray(extra: ByteArray): ExtraData {
                require(extra.size >= EXTRA_LENGTH) {
                    "Extra data must be at least $EXTRA_LENGTH bytes"
                }

                val cryptoAlgorithm = CryptoAlgorithm.fromValue(extra[1].toInt())
                val isControlDocument = (extra[2].toInt() and 0x02) != 0
                val compressionAlgorithm = CompressionAlgorithm.fromValue(
                    ((extra[3].toInt() and 0xFF) shl 8) + (extra[4].toInt() and 0xFF)
                )

                return ExtraData(cryptoAlgorithm, isControlDocument, compressionAlgorithm)
            }
        }
    }

    companion object {
        fun create(
            routingKey: RoutingKey,
            sharedKey: SharedKey,
            extra: ByteArray
        ): ClientChk {
            val extraData = ExtraData.fromByteArray(extra);
            return ClientChk(
                routingKey,
                sharedKey,
                extraData.cryptoAlgorithm,
                emptyList(),
                extraData.isControlDocument,
                extraData.compressionAlgorithm
            )
        }
    }
}

open class ClientSsk(
    routingKey: RoutingKey,
    sharedKey: SharedKey,
    cryptoAlgorithm: CryptoAlgorithm,
    metaStrings: List<String>,
    val publicKey: DSAPublicKey?,
) : ClientKey(routingKey, sharedKey, cryptoAlgorithm, metaStrings.toMutableList()), SubspaceKey {

    final override val docName: String
    val ehDocName: ByteArray

    init {
        require(this.metaStrings.isNotEmpty()) {
            "No meta strings / document name given"
        }

        docName = this.metaStrings.removeFirst()

        // verify publicKey
        if (publicKey != null) {
            val publicKeyBytes = publicKey.bytes
            val publicKeyHash = Hash.digest(HashAlgorithm.SHA256, publicKeyBytes)
            require(publicKeyHash.contentEquals(this.routingKey.bytes)) {
                "Public key hash does not match routing key"
            }
        }

        // calculate ehDocname
        val rijndael256 = Rijndael256(sharedKey.bytes)
        ehDocName =
            rijndael256.encrypt(Hash.digest(HashAlgorithm.SHA256, docName.encodeToByteArray()))
    }

    private data class ExtraData(
        val cryptoAlgorithm: CryptoAlgorithm,
        val isInsertable: Boolean,
    ) {
        fun toByteArray(): ByteArray {
            val extra = ByteArray(EXTRA_LENGTH)
            extra[0] = 1
            extra[1] = if (isInsertable) 1 else 0
            extra[2] = cryptoAlgorithm.value.toByte()
            extra[3] = (1 shr 8).toByte()
            extra[4] = 1
            return extra

        }

        companion object {
            fun fromByteArray(extra: ByteArray): ExtraData {
                require(extra.size >= EXTRA_LENGTH) {
                    "Extra data must be at least $EXTRA_LENGTH bytes"
                }

                val cryptoAlgorithm = CryptoAlgorithm.fromValue(extra[2].toInt())
                val isInsertable = extra[1].toInt() == 1

                return ExtraData(cryptoAlgorithm, isInsertable)
            }
        }
    }

    companion object {
        fun create(
            routingKey: RoutingKey,
            sharedKey: SharedKey,
            extra: ByteArray,
            docName: String,
            publicKey: DSAPublicKey? = null
        ): ClientSsk {
            val extraData = ExtraData.fromByteArray(extra);
            return ClientSsk(
                routingKey,
                sharedKey,
                extraData.cryptoAlgorithm,
                mutableListOf(docName),
                publicKey
            )
        }
    }
}

open class InsertableSsk(
    routingKey: RoutingKey,
    sharedKey: SharedKey,
    cryptoAlgorithm: CryptoAlgorithm,
    docName: String,
    publicKey: DSAPublicKey,
    val privateKey: DSAPrivateKey,
) : ClientSsk(routingKey, sharedKey, cryptoAlgorithm, listOf(docName), publicKey) {

}

class ClientKsk(
    routingKey: RoutingKey,
    sharedKey: SharedKey,
    docName: String,
    publicKey: DSAPublicKey,
    privateKey: DSAPrivateKey
) : InsertableSsk(
    routingKey,
    sharedKey,
    CryptoAlgorithm.AES_PCFB_256_SHA256,
    docName,
    publicKey,
    privateKey
) {

}
package network.crypta.entry.key

import network.crypta.crypto.CryptoAlgorithm
import network.crypta.crypto.DSAPrivateKey
import network.crypta.crypto.DSAPublicKey
import network.crypta.crypto.Hash
import network.crypta.crypto.HashAlgorithm
import network.crypta.crypto.Rijndael256
import network.crypta.entry.RoutingKey
import network.crypta.entry.SharedKey
import network.crypta.entry.Uri
import network.crypta.entry.KeyType

/**
 * Represents a key from the client's perspective, containing all necessary
 * information to either fetch (read) or insert (write) data. It is a specialized
 * type of [AccessKey].
 *
 * @property routingKey The key for locating data on the network.
 * @property sharedKey The key for decrypting the content.
 * @property cryptoAlgorithm The encryption algorithm used for the content.
 * @property metaStrings A list of metadata strings from the URI path.
 */
abstract class ClientKey(
    routingKey: RoutingKey,
    sharedKey: SharedKey,
    cryptoAlgorithm: CryptoAlgorithm,
    metaStrings: MutableList<String>
) : AccessKey(routingKey, sharedKey, cryptoAlgorithm, metaStrings) {

}

/** The length of the "extra" data field in a CHK or SSK URI. */
const val EXTRA_LENGTH = 5

/**
 * Represents a Client Content Hash Key (CHK).
 * CHKs are used for immutable, static content. The key is derived directly from a hash of the content.
 *
 * @property isControlDocument A flag indicating if this is a control document.
 * @property compressionAlgorithm The algorithm used to compress the data.
 */
class ClientChk(
    routingKey: RoutingKey,
    sharedKey: SharedKey,
    cryptoAlgorithm: CryptoAlgorithm,
    metaStrings: List<String>,
    val isControlDocument: Boolean,
    val compressionAlgorithm: CompressionAlgorithm
) : ClientKey(routingKey, sharedKey, cryptoAlgorithm, mutableListOf()) {

    /**
     * Internal data class to manage the serialization of extra metadata for a CHK.
     */
    private data class ExtraData(
        val cryptoAlgorithm: CryptoAlgorithm,
        val isControlDocument: Boolean,
        val compressionAlgorithm: CompressionAlgorithm,
    ) {
        /** Serializes the extra data into a byte array for inclusion in a URI. */
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
            /** Deserializes a byte array from a URI into an [ExtraData] object. */
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
        /**
         * Creates a [ClientChk] from its constituent parts, parsing the `extra` metadata block.
         * @param routingKey The hash of the content.
         * @param sharedKey The key for decrypting the content.
         * @param extra The serialized metadata byte array from the URI.
         * @return A new [ClientChk] instance.
         */
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

        /**
         * Creates a [ClientChk] from the given [Uri].
         *
         * @param uri The URI to parse. Its [Uri.uriType] must be [KeyType.CHK].
         * @return A new [ClientChk] instance populated from the URI.
         */
        fun fromUri(uri: Uri): ClientChk {
            require(uri.uriType == KeyType.CHK) { "URI is not a CHK" }

            val routingKey = uri.keys.routingKey ?: error("Missing routing key")
            val sharedKey = uri.keys.sharedKey ?: error("Missing shared key")
            val extra = uri.keys.getExtraBytes()
            require(extra.size >= EXTRA_LENGTH) { "No extra bytes in CHK" }

            val extraData = ExtraData.fromByteArray(extra)
            return ClientChk(
                routingKey,
                sharedKey,
                extraData.cryptoAlgorithm,
                uri.metaStrings,
                extraData.isControlDocument,
                extraData.compressionAlgorithm
            )
        }
    }
}

/**
 * Represents a Client Signed Subspace Key (SSK).
 * SSKs are used for mutable content where authorship is verified via digital signatures.
 * The routing key is a hash of the creator's public key.
 *
 * @property publicKey The public key associated with this SSK, used for signature verification.
 * @property docName The human-readable name of the document.
 * @property ehDocName The encrypted hash of the document name, used internally.
 */
open class ClientSsk(
    routingKey: RoutingKey,
    sharedKey: SharedKey,
    cryptoAlgorithm: CryptoAlgorithm,
    metaStrings: List<String>,
    val publicKey: DSAPublicKey?,
) : ClientKey(routingKey, sharedKey, cryptoAlgorithm, metaStrings.toMutableList()), SubspaceKey {

    /** The human-readable name of the document. */
    final override val docName: String

    /** The encrypted hash of the document name. */
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

    /**
     * Internal data class to manage the serialization of extra metadata for an SSK.
     */
    private data class ExtraData(
        val cryptoAlgorithm: CryptoAlgorithm,
        val isInsertable: Boolean,
    ) {
        /** Serializes the extra data into a byte array for inclusion in a URI. */
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
            /** Deserializes a byte array from a URI into an [ExtraData] object. */
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
        /**
         * Creates a [ClientSsk] from its constituent parts, parsing the `extra` metadata block.
         *
         * @param routingKey The hash of the public key.
         * @param sharedKey The key for decrypting the content.
         * @param extra The serialized metadata byte array from the URI.
         * @param docName The human-readable name of the document.
         * @param publicKey The optional public key for verification.
         * @return A new [ClientSsk] instance.
         */
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

/**
 * Represents an insertable Client Signed Subspace Key (SSK).
 * This key includes the private key needed to sign and insert new content.
 *
 * @param privateKey The DSA private key used for signing new data.
 */
open class InsertableSsk(
    routingKey: RoutingKey,
    sharedKey: SharedKey,
    cryptoAlgorithm: CryptoAlgorithm,
    docName: String,
    publicKey: DSAPublicKey,
    val privateKey: DSAPrivateKey,
) : ClientSsk(routingKey, sharedKey, cryptoAlgorithm, listOf(docName), publicKey) {

}

/**
 * Represents a Client Keyword Signed Key (KSK).
 * KSKs are a user-friendly type of SSK where the key is derived from a simple
 * human-readable string. This class provides the full insertable key pair.
 *
 * @param routingKey The hash of the public key.
 * @param sharedKey The key for decrypting the content.
 * @param docName The human-readable name that forms the basis of the key.
 * @param publicKey The public key part of the key pair.
 * @param privateKey The private key part of the key pair, for insertions.
 */
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
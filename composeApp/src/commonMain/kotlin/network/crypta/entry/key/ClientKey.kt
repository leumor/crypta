package network.crypta.entry.key

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import network.crypta.crypto.CryptoAlgorithm
import network.crypta.crypto.DsaPrivateKey
import network.crypta.crypto.DsaPublicKey
import network.crypta.crypto.Hash
import network.crypta.crypto.HashAlgorithm
import network.crypta.crypto.Rijndael256
import network.crypta.crypto.toBase64
import network.crypta.entry.KeyType
import network.crypta.entry.RoutingKey
import network.crypta.entry.SharedKey
import network.crypta.entry.Uri

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
) : AccessKey by BasicAccessKey(routingKey, sharedKey, cryptoAlgorithm, metaStrings) {

}

/** The length of the "extra" data field in a CHK or SSK URI. */
const val EXTRA_LENGTH = 5

/** Metadata for SSK and USK keys contained in the `extra` block of a URI. */
data class SskExtraData(
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
        /** Deserializes a byte array from a URI into an [SskExtraData] object. */
        fun fromByteArray(extra: ByteArray): SskExtraData {
            require(extra.size >= EXTRA_LENGTH) {
                "Extra data must be at least $EXTRA_LENGTH bytes"
            }

            val cryptoAlgorithm = CryptoAlgorithm.fromValue(extra[2].toInt())
            val isInsertable = extra[1].toInt() == 1

            return SskExtraData(cryptoAlgorithm, isInsertable)
        }
    }
}

/**
 * Represents a Client Content Hash Key (CHK).
 * CHKs are used for immutable, static content. The key is derived directly from a hash of the content.
 *
 * @property isControlDocument A flag indicating if this is a control document.
 * @property compressionAlgorithm The algorithm used to compress the data.
 */
data class ClientChk(
    override val routingKey: RoutingKey,
    override val sharedKey: SharedKey,
    override val cryptoAlgorithm: CryptoAlgorithm,
    override val metaStrings: MutableList<String>,
    val isControlDocument: Boolean,
    val compressionAlgorithm: CompressionAlgorithm
) : ClientKey(routingKey, sharedKey, cryptoAlgorithm, metaStrings) {

    override fun toString(): String {
        return "${super.toString()}:${routingKey.toBase64()},${sharedKey.toBase64()},$compressionAlgorithm,$isControlDocument,$cryptoAlgorithm"
    }

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
                mutableListOf(),
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
                uri.metaStrings.toMutableList(),
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
data class ClientSsk(
    override val routingKey: RoutingKey,
    override val sharedKey: SharedKey,
    val publicKey: DsaPublicKey?,
    override val docName: String
) : ClientKey(
    routingKey,
    sharedKey,
    CryptoAlgorithm.AES_PCFB_256_SHA256,
    mutableListOf(docName)
), SubspaceKey {

    /** The encrypted hash of the document name. */
    val ehDocName: ByteArray

    constructor(
        routingKey: RoutingKey,
        sharedKey: SharedKey,
        metaStrings: List<String>,
        publicKey: DsaPublicKey?
    ) : this(
        routingKey,
        sharedKey,
        publicKey,
        metaStrings.firstOrNull() ?: error("No meta strings / document name given")
    )

    init {
        if (publicKey != null) {
            val publicKeyBytes = publicKey.bytes
            val publicKeyHash = Hash.digest(HashAlgorithm.SHA256, publicKeyBytes)
            require(publicKeyHash.contentEquals(this.routingKey.bytes)) {
                "Public key hash does not match routing key"
            }
        }

        val rijndael256 = Rijndael256(sharedKey.bytes)
        ehDocName =
            rijndael256.encrypt(Hash.digest(HashAlgorithm.SHA256, docName.encodeToByteArray()))
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
            publicKey: DsaPublicKey? = null
        ): ClientSsk {
            val extraData = SskExtraData.fromByteArray(extra);

            require(extraData.cryptoAlgorithm == CryptoAlgorithm.AES_PCFB_256_SHA256) {
                "Unknown encryption algorithm ${extraData.cryptoAlgorithm}"
            }

            return ClientSsk(
                routingKey,
                sharedKey,
                publicKey,
                docName
            )
        }

        /**
         * Creates a [ClientSsk] from the given [Uri].
         *
         * @param uri The URI to parse. Its [Uri.uriType] must be [KeyType.SSK].
         * @return A new [ClientSsk] instance populated from the URI.
         */
        fun fromUri(uri: Uri): ClientSsk {
            require(uri.uriType == KeyType.SSK) { "URI is not an SSK" }

            val routingKey = uri.keys.routingKey ?: error("Missing routing key")
            val sharedKey = uri.keys.sharedKey ?: error("Missing shared key")
            val extra = uri.keys.getExtraBytes()

            return create(routingKey, sharedKey, extra, uri.metaStrings.first())
        }
    }
}

/**
 * Represents an insertable Client Signed Subspace Key (SSK).
 * This key includes the private key needed to sign and insert new content.
 *
 * @param privateKey The DSA private key used for signing new data.
 */
data class InsertableClientSsk(
    val clientSsk: ClientSsk,
    override val privateKey: DsaPrivateKey
) : SubspaceKey by clientSsk,
    Insertable,
    AccessKey by clientSsk {

    val publicKey: DsaPublicKey get() = clientSsk.publicKey!!
    val ehDocName: ByteArray get() = clientSsk.ehDocName

    companion object {
        /**
         * Creates an [InsertableClientSsk] from the given [Uri].
         *
         * The URI must contain a private key (as the routing key in Uri) and use the SSK type. Only the
         * AES-PCFB-256-SHA256 cryptosystem is currently supported.
         */
        fun fromUri(uri: Uri): InsertableClientSsk {
            require(uri.uriType == KeyType.SSK) { "Not a valid SSK insert URI type: ${'$'}{uri.uriType}" }

            val routingKey = uri.keys.routingKey
                ?: error("Insertable SSK URIs must have a routing key!")
            val sharedKey = uri.keys.sharedKey
                ?: error("Insertable SSK URIs must have a private key!")
            val extra = uri.keys.getExtraBytes()

            val extraData = SskExtraData.fromByteArray(extra);

            require(extraData.isInsertable) { "SSK not an insertable key" }
            require(extraData.cryptoAlgorithm == CryptoAlgorithm.AES_PCFB_256_SHA256) {
                "Unrecognized crypto type in SSK private key"
            }

            val docName = uri.metaStrings.firstOrNull()
                ?: error("SSK URIs must have a document name (to avoid ambiguity)")

            val x = BigInteger.fromByteArray(routingKey.bytes, Sign.POSITIVE)
            val privKey = DsaPrivateKey(x)
            val pubKey = DsaPublicKey.fromPrivateKey(privKey)
            val hash = Hash.digest(HashAlgorithm.SHA256, pubKey.bytes)
            val pkHash = RoutingKey(hash)

            val ssk = ClientSsk(pkHash, sharedKey, pubKey, docName)
            return InsertableClientSsk(ssk, privKey)
        }
    }
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
data class ClientKsk(
    val insertableSsk: InsertableClientSsk
) : SubspaceKey by insertableSsk,
    Insertable by insertableSsk,
    AccessKey by insertableSsk {

    val publicKey: DsaPublicKey get() = insertableSsk.publicKey
    val ehDocName: ByteArray get() = insertableSsk.ehDocName
}

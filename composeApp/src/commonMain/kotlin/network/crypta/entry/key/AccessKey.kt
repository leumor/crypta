package network.crypta.entry.key

import network.crypta.crypto.CryptoAlgorithm
import network.crypta.crypto.DsaPrivateKey
import network.crypta.entry.KeyType
import network.crypta.entry.RoutingKey
import network.crypta.entry.SharedKey
import network.crypta.entry.Uri
import network.crypta.entry.key.ClientSsk
import network.crypta.entry.key.InsertableClientSsk

/**
 * An abstract representation of a key that provides access to data.
 * It forms the basis for keys that can be resolved to content, like [Usk] and [ClientKey].
 *
 * @property routingKey The key for locating data on the network.
 * @property sharedKey The key for decrypting the content. Nullable for keys that might not have one.
 * @property cryptoAlgorithm The encryption algorithm used for the content.
 * @property metaStrings A list of metadata strings from the URI path.
 */
abstract class AccessKey(
    routingKey: RoutingKey,
    val sharedKey: SharedKey,
    cryptoAlgorithm: CryptoAlgorithm,
    val metaStrings: MutableList<String>
) : Key(routingKey, cryptoAlgorithm) {

}

/**
 * An interface for keys that belong to a "subspace", a concept in Crypta
 * for a collection of related documents under a single identity.
 * SSKs, USKs, and KSKs are all subspace keys.
 *
 * @property docName The human-readable name of the document within the subspace.
 */
interface SubspaceKey {
    val docName: String
}

/**
 * An interface for keys that can be used to insert or update content on the network.
 * This requires a private key for signing.
 *
 * @property privateKey The DSA private key for signing new data insertions.
 */
interface Insertable {
    val privateKey: DsaPrivateKey
}

/**
 * Represents an Updatable Subspace Key (USK).
 * USKs are a type of [AccessKey] used for mutable content, such as a website that needs updates.
 * They point to a specific version of a document, but can be resolved to the latest version.
 *
 * @param routingKey The key for locating the USK data.
 * @param sharedKey The key for decrypting the USK data.
 * @param cryptoAlgorithm The encryption algorithm used.
 * @param metaStrings The metadata from the URI, which must include the document name and edition.
 *
 * @property docName The name of the document, often called the "site name".
 * @property suggestedEdition The specific version number of the document this key points to.
 */
open class Usk(
    routingKey: RoutingKey,
    sharedKey: SharedKey,
    cryptoAlgorithm: CryptoAlgorithm,
    metaStrings: List<String>
) : AccessKey(routingKey, sharedKey, cryptoAlgorithm, metaStrings.toMutableList()), SubspaceKey {
    /**
     * The human-readable name of the document. In the context of a freesite, this is the "site name".
     */
    final override val docName: String


    /**
     * The suggested edition number of the document. This allows clients to request a specific
     * version, though they will typically seek the latest one.
     */
    val suggestedEdition: Long

    init {
        require(this.metaStrings.isNotEmpty()) {
            "No meta strings / document name given"
        }

        docName = this.metaStrings.removeFirst()

        require(this.metaStrings.isNotEmpty()) {
            "No suggested edition number"
        }

        try {
            suggestedEdition = this.metaStrings.removeFirst().toLong()
        } catch (e: NumberFormatException) {
            throw IllegalArgumentException("Invalid suggested edition number", e)
        }
    }

    /**
     * Secondary constructor for creating a [Usk] with explicit document name and edition.
     *
     * @param routingKey The key for locating the USK data.
     * @param sharedKey The key for decrypting the USK data.
     * @param cryptoAlgorithm The encryption algorithm used.
     * @param docName The human-readable name of the document.
     * @param suggestedEdition The version number of the document.
     */
    constructor(
        routingKey: RoutingKey,
        sharedKey: SharedKey,
        cryptoAlgorithm: CryptoAlgorithm,
        docName: String,
        suggestedEdition: Long
    ) : this(
        routingKey,
        sharedKey,
        cryptoAlgorithm,
        listOf(docName, suggestedEdition.toString())
    )

    companion object {
        /**
         * Parses a [Uri] into a [Usk].
         * The URI must have type [KeyType.USK].
         */
        fun fromUri(uri: Uri): Usk {
            require(uri.uriType == KeyType.USK) { "URI is not a USK" }

            val docName = uri.metaStrings.firstOrNull()
                ?: error("USK URIs must have a document name")
            val sskUri = Uri(KeyType.SSK, uri.keys, listOf(docName))
            val ssk = ClientSsk.fromUri(sskUri)

            return Usk(ssk.routingKey, ssk.sharedKey, ssk.cryptoAlgorithm, uri.metaStrings)
        }
    }
}

/**
 * An insertable Updatable Subspace Key (USK).
 * This key contains the [DsaPrivateKey] necessary to sign and insert new versions
 * of the content into the subspace.
 *
 * @param routingKey The key for locating the USK data.
 * @param sharedKey The key for decrypting the USK data.
 * @param cryptoAlgorithm The encryption algorithm used.
 * @param docName The human-readable name of the document.
 * @param suggestedEdition The version number of the document being inserted.
 * @param privateKey The private key required for signing the new content.
 */
class InsertableUsk(
    routingKey: RoutingKey,
    sharedKey: SharedKey,
    cryptoAlgorithm: CryptoAlgorithm,
    docName: String,
    suggestedEdition: Long,
    override val privateKey: DsaPrivateKey
) : Usk(routingKey, sharedKey, cryptoAlgorithm, docName, suggestedEdition), Insertable {
    companion object {
        /**
         * Parses an insertable USK [Uri] into an [InsertableUsk].
         * The URI must use the [KeyType.USK] type and include a private key.
         */
        fun fromUri(uri: Uri): InsertableUsk {
            require(uri.uriType == KeyType.USK) { "Not a valid USK insert URI type: ${'$'}{uri.uriType}" }

            val docName = uri.metaStrings.firstOrNull()
                ?: error("USK URIs must have a document name")
            val editionStr = uri.metaStrings.getOrNull(1)
                ?: error("USK URIs must have an edition number")

            val sskUri = Uri(KeyType.SSK, uri.keys, listOf(docName))
            val ssk = InsertableClientSsk.fromUri(sskUri)

            val edition = editionStr.toLong()

            return InsertableUsk(
                ssk.routingKey,
                ssk.sharedKey,
                ssk.cryptoAlgorithm,
                docName,
                edition,
                ssk.privateKey
            )
        }
    }
}
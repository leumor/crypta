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
/**
 * A key that grants access to data. Concrete implementations delegate the
 * property storage to [BasicAccessKey] for convenience.
 */
sealed interface AccessKey : Key {
    val sharedKey: SharedKey
    val metaStrings: MutableList<String>
}

/** Simple data holder implementing [AccessKey]. */
data class BasicAccessKey(
    override val routingKey: RoutingKey,
    override val sharedKey: SharedKey,
    override val cryptoAlgorithm: CryptoAlgorithm,
    override val metaStrings: MutableList<String>
) : AccessKey, Key by BasicKey(routingKey, cryptoAlgorithm)

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
data class Usk(
    override val routingKey: RoutingKey,
    override val sharedKey: SharedKey,
    override val cryptoAlgorithm: CryptoAlgorithm,
    override val docName: String,
    val suggestedEdition: Long
) : SubspaceKey,
    AccessKey by BasicAccessKey(
        routingKey,
        sharedKey,
        cryptoAlgorithm,
        mutableListOf(docName, suggestedEdition.toString())
    ) {

    constructor(
        routingKey: RoutingKey,
        sharedKey: SharedKey,
        cryptoAlgorithm: CryptoAlgorithm,
        metaStrings: List<String>
    ) : this(
        routingKey,
        sharedKey,
        cryptoAlgorithm,
        metaStrings.firstOrNull()
            ?: error("No meta strings / document name given"),
        metaStrings.getOrNull(1)?.toLongOrNull()
            ?: error("Invalid suggested edition number")
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
data class InsertableUsk(
    override val routingKey: RoutingKey,
    override val sharedKey: SharedKey,
    override val cryptoAlgorithm: CryptoAlgorithm,
    override val docName: String,
    val suggestedEdition: Long,
    override val privateKey: DsaPrivateKey
) : SubspaceKey,
    Insertable,
    AccessKey by BasicAccessKey(
        routingKey,
        sharedKey,
        cryptoAlgorithm,
        mutableListOf(docName, suggestedEdition.toString())
    ) {
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

package network.crypta.entry.key

import network.crypta.crypto.CryptoAlgorithm
import network.crypta.crypto.DSAPrivateKey

abstract class AccessKey(
    routingKey: RoutingKey,
    val sharedKey: SharedKey?,
    cryptoAlgorithm: CryptoAlgorithm,
    val metaStrings: MutableList<String>
) : Key(routingKey, cryptoAlgorithm) {

}

interface SubspaceKey {
    val docName: String
}

interface Insertable {
    val privateKey: DSAPrivateKey
}

open class Usk(
    routingKey: RoutingKey,
    sharedKey: SharedKey,
    cryptoAlgorithm: CryptoAlgorithm,
    metaStrings: List<String>
) : AccessKey(routingKey, sharedKey, cryptoAlgorithm, metaStrings.toMutableList()), SubspaceKey {
    final override val docName: String // it's called "siteName" in Freenet
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
}

class InsertableUsk(
    routingKey: RoutingKey,
    sharedKey: SharedKey,
    cryptoAlgorithm: CryptoAlgorithm,
    docName: String,
    suggestedEdition: Long,
    override val privateKey: DSAPrivateKey
) : Usk(routingKey, sharedKey, cryptoAlgorithm, docName, suggestedEdition), Insertable {

}
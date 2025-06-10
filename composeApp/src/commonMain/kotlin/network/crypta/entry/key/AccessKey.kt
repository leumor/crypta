package network.crypta.entry.key

import network.crypta.crypto.CryptoAlgorithm

abstract class AccessKey(
    routingKey: RoutingKey,
    val sharedKey: SharedKey?,
    cryptoAlgorithm: CryptoAlgorithm,
    val metaStrings: MutableList<String>
) : Key(routingKey, cryptoAlgorithm) {

}

class Usk(
    routingKey: RoutingKey,
    sharedKey: SharedKey,
    cryptoAlgorithm: CryptoAlgorithm,
    metaStrings: MutableList<String>
) : AccessKey(routingKey, sharedKey, cryptoAlgorithm, metaStrings) {
    val docName: String
    val suggestedEdition: Long

    init {
        require(!metaStrings.isEmpty()) {
            "No meta strings / document name given"
        }

        docName = metaStrings.removeFirst()

        require(!metaStrings.isEmpty()) {
            "No suggested edition number"
        }

        try {
            suggestedEdition = metaStrings.removeFirst().toLong()
        } catch (e: NumberFormatException) {
            throw IllegalArgumentException("Invalid suggested edition number", e)
        }
    }
}
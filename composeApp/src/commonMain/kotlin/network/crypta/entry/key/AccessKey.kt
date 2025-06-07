package network.crypta.entry.key

abstract class AccessKey(
    routingKey: RoutingKey,
    val decryptionKey: DecryptionKey?,
    cryptoAlgorithm: CryptoAlgorithm,
    val metaStrings: List<String>
) : Key(routingKey, cryptoAlgorithm) {

} 
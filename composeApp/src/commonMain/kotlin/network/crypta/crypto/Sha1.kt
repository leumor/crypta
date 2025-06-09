package network.crypta.crypto

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA1
import dev.whyoleg.cryptography.DelicateCryptographyApi

object Sha1 {
    @OptIn(DelicateCryptographyApi::class)
    fun digest(data: ByteArray): ByteArray {
        return CryptographyProvider.Default
            .get(SHA1)
            .hasher()
            .hashBlocking(data)
    }
}

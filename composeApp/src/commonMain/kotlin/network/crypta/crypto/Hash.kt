package network.crypta.crypto

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.SHA1
import dev.whyoleg.cryptography.algorithms.SHA256

enum class HashAlgorithm {
    SHA1,
    SHA256,
}

object Hash {
    @OptIn(DelicateCryptographyApi::class)
    fun digest(algorithm: HashAlgorithm, data: ByteArray): ByteArray {
        val algo = when (algorithm) {
            HashAlgorithm.SHA1 -> SHA1
            HashAlgorithm.SHA256 -> SHA256
        }
        return CryptographyProvider.Default
            .get(algo)
            .hasher()
            .hashBlocking(data)
    }

    @OptIn(DelicateCryptographyApi::class)
    fun hasher(algorithm: HashAlgorithm): Hasher {
        val algo = when (algorithm) {
            HashAlgorithm.SHA1 -> SHA1
            HashAlgorithm.SHA256 -> SHA256
        }
        val function = CryptographyProvider.Default
            .get(algo)
            .hasher()
            .createHashFunction()
        return Hasher(function)
    }
}

class Hasher internal constructor(
    private val fn: dev.whyoleg.cryptography.operations.HashFunction,
) {
    fun update(data: ByteArray, offset: Int = 0, length: Int = data.size) {
        fn.update(data, offset, length)
    }

    fun digest(): ByteArray {
        val out = fn.hashToByteArray()
        fn.reset()
        return out
    }
}

package network.crypta.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals

class HashTest {
    @Test
    fun testIncremental() {
        val data = "hello world".encodeToByteArray()
        val expected = Hash.digest(HashAlgorithm.SHA256, data)
        val hasher = Hash.hasher(HashAlgorithm.SHA256)
        hasher.update(data.sliceArray(0..4))
        hasher.update(data.sliceArray(5 until data.size))
        val actual = hasher.digest()
        assertContentEquals(expected, actual)
    }
}

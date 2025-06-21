package network.crypta.network

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class TransportTest {
    @Test
    fun udpTransportRoundTrip() = runTest {
        val transportA = UdpTransport("127.0.0.1", 0)
        val transportB = UdpTransport("127.0.0.1", 0)

        val fromA = CompletableDeferred<ByteArray>()
        val fromB = CompletableDeferred<ByteArray>()

        transportA.onDataReceived = { _, data -> fromA.complete(data) }
        transportB.onDataReceived = { _, data -> fromB.complete(data) }

        val endA = transportA.localEndpoint()
        val endB = transportB.localEndpoint()

        transportA.send(endB, "hello".encodeToByteArray())
        transportB.send(endA, "world".encodeToByteArray())

        assertEquals("hello", fromB.await().decodeToString())
        assertEquals("world", fromA.await().decodeToString())

        transportA.close()
        transportB.close()
    }
}
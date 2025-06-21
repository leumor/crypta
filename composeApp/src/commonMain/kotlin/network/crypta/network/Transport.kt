package network.crypta.network

import com.eygraber.uri.Uri
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.BoundDatagramSocket
import io.ktor.network.sockets.Datagram
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.utils.io.core.buildPacket
import io.ktor.utils.io.core.writeFully
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.io.readByteArray

/**
 * Basic transport abstraction used for network communication.
 */
interface Transport<E : Endpoint> {
    /** Callback invoked when a datagram is received. */
    var onDataReceived: suspend (endpoint: E, data: ByteArray) -> Unit

    /** Send [data] to the remote [endpoint]. */
    suspend fun send(endpoint: E, data: ByteArray)

    /** Release any resources associated with this transport. */
    suspend fun close()
}

/**
 * UDP implementation of [Transport] based on Ktor sockets.
 *
 * @param localHost host to bind the underlying socket to
 * @param port local port to bind
 * @param dispatcher dispatcher used for internal coroutines
 * @param bufferCapacity size of the buffer for incoming datagrams
 */
class UdpTransport(
    private val localHost: String,
    private val port: Int,
    dispatcher: CoroutineDispatcher = Dispatchers.Default,
    bufferCapacity: Int = 16,
) : Transport<UdpEndPoint> {
    override var onDataReceived: suspend (UdpEndPoint, ByteArray) -> Unit = { _, _ -> }

    private val job = SupervisorJob()
    private val scope = CoroutineScope(job + dispatcher)

    private val selector = SelectorManager(dispatcher)
    private val socketDeferred = CompletableDeferred<BoundDatagramSocket>(job)
    private val endpointDeferred = CompletableDeferred<UdpEndPoint>(job)

    private val datagramChannel = Channel<Datagram>(capacity = bufferCapacity)

    init {
        scope.launch {
            for (datagram in datagramChannel) {
                val data = datagram.packet.readByteArray()
                val addr = datagram.address as InetSocketAddress
                onDataReceived(UdpEndPoint(Uri.parse("udp://${addr.hostname}:${addr.port}")), data)
            }
        }

        scope.launch {
            try {
                val socket = aSocket(selector).udp().bind(InetSocketAddress(localHost, port))
                socketDeferred.complete(socket)
                val addr = socket.localAddress as InetSocketAddress
                val ep = UdpEndPoint(Uri.parse("udp://${addr.hostname}:${addr.port}"))
                endpointDeferred.complete(ep)
                try {
                    for (datagram in socket.incoming) {
                        datagramChannel.send(datagram)
                    }
                } catch (e: CancellationException) {
                    // normal shutdown
                } catch (e: Throwable) {
                    datagramChannel.close(e)
                    throw e
                }
            } catch (e: Exception) {
                socketDeferred.completeExceptionally(e)
                endpointDeferred.completeExceptionally(e)
                datagramChannel.close(e)
            }
        }
    }

    /** Returns the local endpoint this transport is bound to. */
    suspend fun localEndpoint(): UdpEndPoint = endpointDeferred.await()

    override suspend fun send(endpoint: UdpEndPoint, data: ByteArray) {
        val packet = buildPacket { writeFully(data) }
        val host = endpoint.host ?: error("Endpoint host missing")
        val addr = InetSocketAddress(host, endpoint.port)
        val socket = socketDeferred.await()
        socket.send(Datagram(packet, addr))
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    override suspend fun close() {
        job.cancelAndJoin()
        datagramChannel.close()
        if (socketDeferred.isCompleted) {
            socketDeferred.getCompleted().close()
        }
    }
}


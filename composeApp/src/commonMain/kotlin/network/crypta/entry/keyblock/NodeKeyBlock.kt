package network.crypta.entry.keyblock

import network.crypta.entry.key.NodeChk
import network.crypta.entry.key.NodeKey
import network.crypta.entry.key.NodeSsk

interface NodeKeyBlock<K : NodeKey> {
    val data: ByteArray
    val headers: ByteArray
    val nodeKey: K
}

data class NodeChkBlock(
    override val data: ByteArray,
    override val headers: ByteArray,
    override val nodeKey: NodeChk
) : NodeKeyBlock<NodeChk> {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as NodeChkBlock

        if (!data.contentEquals(other.data)) return false
        if (!headers.contentEquals(other.headers)) return false
        if (nodeKey != other.nodeKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + headers.contentHashCode()
        result = 31 * result + nodeKey.hashCode()
        return result
    }
}

data class NodeSskBlock(
    override val data: ByteArray,
    override val headers: ByteArray,
    override val nodeKey: NodeSsk
) : NodeKeyBlock<NodeSsk> {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as NodeSskBlock

        if (!data.contentEquals(other.data)) return false
        if (!headers.contentEquals(other.headers)) return false
        if (nodeKey != other.nodeKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + headers.contentHashCode()
        result = 31 * result + nodeKey.hashCode()
        return result
    }
}

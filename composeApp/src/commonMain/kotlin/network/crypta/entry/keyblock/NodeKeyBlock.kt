package network.crypta.entry.keyblock

import network.crypta.entry.key.NodeChk
import network.crypta.entry.key.NodeKey
import network.crypta.entry.key.NodeSsk

abstract class NodeKeyBlock<K : NodeKey>(
    val data: ByteArray,
    val headers: ByteArray,
    val nodeKey: K
) {
}

class NodeChkBlock(data: ByteArray, headers: ByteArray, nodeKey: NodeChk) :
    NodeKeyBlock<NodeChk>(data, headers, nodeKey)

class NodeSskBlock(data: ByteArray, headers: ByteArray, nodeKey: NodeSsk) :
    NodeKeyBlock<NodeSsk>(data, headers, nodeKey)

package network.crypta.entry.keyblock

import network.crypta.entry.key.ClientChk
import network.crypta.entry.key.ClientKey
import network.crypta.entry.key.ClientSsk

interface ClientKeyBlock<C : ClientKey, B : NodeKeyBlock<*>> {
    val nodeKeyBlock: B
    val clientKey: C
}

data class ClientChkBlock(
    override val nodeKeyBlock: NodeChkBlock,
    override val clientKey: ClientChk
) : ClientKeyBlock<ClientChk, NodeChkBlock>

data class ClientSskBlock(
    override val nodeKeyBlock: NodeSskBlock,
    override val clientKey: ClientSsk
) : ClientKeyBlock<ClientSsk, NodeSskBlock>
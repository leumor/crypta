package network.crypta.network

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class MessageTypeRoundTripTest {
    @Test
    fun packetTransmitRoundTrip() {
        val msg = PacketTransmit(42L, 5, true, byteArrayOf(1, 2, 3, 4))
        val bytes = encode(msg)
        val decoded = decode<PacketTransmit>(bytes)
        assertEquals(msg.uid, decoded.uid)
        assertEquals(msg.packetNo, decoded.packetNo)
        assertEquals(msg.sent, decoded.sent)
        assertContentEquals(msg.data, decoded.data)
        assertEquals("packetTransmit", decoded.metaData.messageTypeName)
        assertEquals(Priority.BULK_DATA, decoded.metaData.priority)
        assertEquals(false, decoded.metaData.isLossyPacketMessage)
    }

    @Test
    fun fnpRejectedOverloadRoundTrip() {
        val msg = FNPRejectedOverload(77L, true)
        val bytes = encode(msg)
        val decoded = decode<FNPRejectedOverload>(bytes)
        assertEquals(msg.uid, decoded.uid)
        assertEquals(msg.isLocal, decoded.isLocal)
        assertEquals("FNPRejectOverload", decoded.metaData.messageTypeName)
        assertEquals(Priority.HIGH, decoded.metaData.priority)
        assertEquals(false, decoded.metaData.isLossyPacketMessage)
    }

    @Test
    fun fnpChkDataFoundRoundTrip() {
        val msg = FNPCHKDataFound(123L, byteArrayOf(9, 8, 7))
        val bytes = encode(msg)
        val decoded = decode<FNPCHKDataFound>(bytes)
        assertEquals(msg.uid, decoded.uid)
        assertContentEquals(msg.blockHeaders, decoded.blockHeaders)
        assertEquals("FNPCHKDataFound", decoded.metaData.messageTypeName)
        assertEquals(Priority.UNSPECIFIED, decoded.metaData.priority)
        assertEquals(false, decoded.metaData.isLossyPacketMessage)
    }

    @Test
    fun fnpRealTimeFlagRoundTrip() {
        val msg = FNPRealTimeFlag(false)
        val bytes = encode(msg)
        val decoded = decode<FNPRealTimeFlag>(bytes)
        assertEquals(msg.realTimeFlag, decoded.realTimeFlag)
        assertEquals("FNPRealTimeFlag", decoded.metaData.messageTypeName)
        assertEquals(Priority.HIGH, decoded.metaData.priority)
        assertEquals(false, decoded.metaData.isLossyPacketMessage)
    }
}

@file:UseContextualSerialization
// Unimplemented message types from DMT.java: none
// Message types whose complex fields were simplified to ByteArray:
// PacketTransmit, FNPBulkPacketSend, TestSendCHK, TestRequest, TestDataReply,
// NodeToNodeMessage, FNPCHKDataRequest, FNPSSKDataRequest, FNPCHKDataFound,
// FNPInsertRequest, FNPDataInsert, FNPSSKInsertRequest, FNPSSKInsertRequestNew,
// FNPSSKInsertRequestHeaders, FNPSSKInsertRequestData, FNPSSKDataFoundHeaders,
// FNPSSKDataFoundData, FNPSSKPubKey, FNPOfferKey, FNPGetOfferedKey,
// ProbeRejectStats, FNPSwapRequest, FNPSwapReply, FNPSwapCommit, FNPSwapComplete,
// FNPLocChangeNotificationNew, FNPRoutedPing, FNPDetectedIPAddress,
// FNPSentPackets, FNPDisconnect, UOMFetchDependency, FNPSwapNodeUIDs,
// FNPBestRoutesNotTaken, FNPCheckStillRunning, FNPIsStillRunning
package network.crypta.network

import kotlinx.serialization.Serializable
import kotlinx.serialization.UseContextualSerialization
import kotlinx.serialization.Transient

/**
 * Represents the priority level of a network message.
 */
@Serializable
enum class Priority {
    /** Very urgent */
    NOW,
    /** Short timeout, or urgent for other reasons - Accepted, RejectedLoop etc. */
    HIGH,
    /** Stuff that completes a request, and miscellaneous stuff. */
    UNSPECIFIED,
    /** Stuff that starts a request. */
    LOW,
    /** Bulk data transfer for realtime requests. */
    REALTIME_DATA,
    /**
     * Bulk data transfer, bottom of the heap, high level limiting must ensure there is
     * time to send it by not accepting an infeasible number of requests.
     */
    BULK_DATA,
}

/** Metadata describing a particular message type. */
interface MessageTypeMetaData {
    val messageTypeName: String
    val priority: Priority
    val isLossyPacketMessage: Boolean
}

/** Interface describing a serialized network message. */
interface MessageType {
    @Transient
    val metaData: MessageTypeMetaData
}

/** Serializable representation of the `packetTransmit` message from DMT.java. */
@Serializable
class PacketTransmit(
    val uid: Long,
    val packetNo: Int,
    val sent: Boolean,
    val data: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "packetTransmit"
        override val priority = Priority.BULK_DATA
        override val isLossyPacketMessage = false
    }
}

@Serializable
class AllSent(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "allSent"
        override val priority = Priority.BULK_DATA
        override val isLossyPacketMessage = false
    }
}

@Serializable
class AllReceived(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "allReceived"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class SendAborted(
    val uid: Long,
    val description: String,
    val reason: Int,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "sendAborted"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPBulkPacketSend(
    val uid: Long,
    val packetNo: Int,
    val data: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPBulkPacketSend"
        override val priority = Priority.BULK_DATA
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPBulkSendAborted(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPBulkSendAborted"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPBulkReceiveAborted(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPBulkReceiveAborted"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPBulkReceivedAll(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPBulkReceivedAll"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class TestTransferSend(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "testTransferSend"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class TestTransferSendAck(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "testTransferSendAck"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class TestSendCHK(
    val uid: Long,
    val freenetUri: String,
    val chkHeader: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "testSendCHK"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class TestRequest(
    val uid: Long,
    val freenetRoutingKey: ByteArray,
    val htl: Int,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "testRequest"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class TestDataNotFound(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "testDataNotFound"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class TestDataReply(
    val uid: Long,
    val testChkHeaders: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "testDataReply"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class TestSendCHKAck(
    val uid: Long,
    val freenetUri: String,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "testSendCHKAck"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class TestDataReplyAck(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "testDataReplyAck"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class TestDataNotFoundAck(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "testDataNotFoundAck"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class TestReceiveCompleted(
    val uid: Long,
    val success: Boolean,
    val reason: String,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "testReceiveCompleted"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class TestSendCompleted(
    val uid: Long,
    val success: Boolean,
    val reason: String,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "testSendCompleted"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class NodeToNodeMessage(
    val nodeToNodeMessageType: Int,
    val nodeToNodeMessageData: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "nodeToNodeMessage"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPCHKDataRequest(
    val uid: Long,
    val htl: Short,
    val nearestLocation: Double,
    val freenetRoutingKey: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPCHKDataRequest"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSSKDataRequest(
    val uid: Long,
    val htl: Short,
    val nearestLocation: Double,
    val freenetRoutingKey: ByteArray,
    val needPubKey: Boolean,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSSKDataRequest"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPRejectedLoop(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPRejectLoop"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPRejectedOverload(
    val uid: Long,
    val isLocal: Boolean,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPRejectOverload"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPAccepted(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPAccepted"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPDataNotFound(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPDataNotFound"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPRecentlyFailed(
    val uid: Long,
    val timeLeft: Int,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPRecentlyFailed"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPCHKDataFound(
    val uid: Long,
    val blockHeaders: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPCHKDataFound"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPRouteNotFound(
    val uid: Long,
    val htl: Short,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPRouteNotFound"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPInsertRequest(
    val uid: Long,
    val htl: Short,
    val nearestLocation: Double,
    val freenetRoutingKey: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPInsertRequest"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPInsertReply(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPInsertReply"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPDataInsert(
    val uid: Long,
    val blockHeaders: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPDataInsert"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPInsertTransfersCompleted(
    val uid: Long,
    val anyTimedOut: Boolean,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPInsertTransfersCompleted"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPRejectedTimeout(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPTooSlow"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPDataInsertRejected(
    val uid: Long,
    val reason: Short,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPDataInsertRejected"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSSKInsertRequest(
    val uid: Long,
    val htl: Short,
    val freenetRoutingKey: ByteArray,
    val nearestLocation: Double,
    val blockHeaders: ByteArray,
    val pubkeyHash: ByteArray,
    val data: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSSKInsertRequest"
        override val priority = Priority.BULK_DATA
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSSKInsertRequestNew(
    val uid: Long,
    val htl: Short,
    val freenetRoutingKey: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSSKInsertRequestNew"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSSKInsertRequestHeaders(
    val uid: Long,
    val blockHeaders: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSSKInsertRequestHeaders"
        override val priority = Priority.BULK_DATA
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSSKInsertRequestData(
    val uid: Long,
    val data: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSSKInsertRequestData"
        override val priority = Priority.BULK_DATA
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSSKDataFoundHeaders(
    val uid: Long,
    val blockHeaders: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSSKDataFoundHeaders"
        override val priority = Priority.BULK_DATA
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSSKDataFoundData(
    val uid: Long,
    val data: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSSKDataFoundData"
        override val priority = Priority.BULK_DATA
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSSKAccepted(
    val uid: Long,
    val needPubKey: Boolean,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSSKAccepted"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSSKPubKey(
    val uid: Long,
    val pubkeyAsBytes: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSSKPubKey"
        override val priority = Priority.BULK_DATA
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSSKPubKeyAccepted(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSSKPubKeyAccepted"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPOpennetCompletedAck(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPOpennetCompletedAck"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPOpennetCompletedTimeout(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPOpennetCompletedTimeout"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPOpennetConnectDestinationNew(
    val uid: Long,
    val transferUid: Long,
    val noderefLength: Int,
    val paddedLength: Int,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPConnectDestinationNew"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPOpennetConnectReplyNew(
    val uid: Long,
    val transferUid: Long,
    val noderefLength: Int,
    val paddedLength: Int,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPConnectReplyNew"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPOpennetAnnounceRequest(
    val uid: Long,
    val transferUid: Long,
    val noderefLength: Int,
    val paddedLength: Int,
    val htl: Short,
    val nearestLocation: Double,
    val targetLocation: Double,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPOpennetAnnounceRequest"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPOpennetAnnounceReply(
    val uid: Long,
    val transferUid: Long,
    val noderefLength: Int,
    val paddedLength: Int,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPOpennetAnnounceReply"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPOpennetAnnounceCompleted(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPOpennetAnnounceCompleted"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPOpennetDisabled(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPOpennetDisabled"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPOpennetNoderefRejected(
    val uid: Long,
    val rejectCode: Int,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPOpennetNoderefRejected"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPOpennetAnnounceNodeNotWanted(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPOpennetAnnounceNodeNotWanted"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPOfferKey(
    val key: ByteArray,
    val offerAuthenticator: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPOfferKey"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPGetOfferedKey(
    val key: ByteArray,
    val offerAuthenticator: ByteArray,
    val needPubKey: Boolean,
    val uid: Long,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPGetOfferedKey"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPGetOfferedKeyInvalid(
    val uid: Long,
    val reason: Short,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPGetOfferedKeyInvalid"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPPing(val pingSeqNo: Int) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPPing"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPPong(val pingSeqNo: Int) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPPong"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPRHProbeReply(
    val uid: Long,
    val nearestLocation: Double,
    val bestLocation: Double,
    val counter: Short,
    val uniqueCounter: Short,
    val linearCounter: Short,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPRHProbeReply"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class ProbeRequest(
    val htl: Byte,
    val uid: Long,
    val type: Byte,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "ProbeRequest"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class ProbeError(
    val uid: Long,
    val type: Byte,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "ProbeError"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class ProbeRefused(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "ProbeRefused"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class ProbeBandwidth(
    val uid: Long,
    val outputBandwidthUpperLimit: Float,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "ProbeBandwidth"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class ProbeBuild(
    val uid: Long,
    val build: Int,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "ProbeBuild"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class ProbeIdentifier(
    val uid: Long,
    val probeIdentifier: Long,
    val uptimePercent: Byte,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "ProbeIdentifier"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class ProbeLinkLengths(
    val uid: Long,
    val linkLengths: FloatArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "ProbeLinkLengths"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class ProbeLocation(
    val uid: Long,
    val location: Float,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "ProbeLocation"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class ProbeStoreSize(
    val uid: Long,
    val storeSize: Float,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "ProbeStoreSize"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class ProbeUptime(
    val uid: Long,
    val uptimePercent: Float,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "ProbeUptime"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class ProbeRejectStats(
    val uid: Long,
    val rejectStats: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "ProbeRejectStats"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class ProbeOverallBulkOutputCapacityUsage(
    val uid: Long,
    val outputBandwidthClass: Byte,
    val capacityUsage: Float,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "ProbeOverallBulkOutputCapacityUsage"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSwapRequest(
    val uid: Long,
    val hash: ByteArray,
    val htl: Int,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSwapRequest"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSwapRejected(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSwapRejected"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSwapReply(
    val uid: Long,
    val hash: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSwapReply"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSwapCommit(
    val uid: Long,
    val data: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSwapCommit"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSwapComplete(
    val uid: Long,
    val data: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSwapComplete"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPLocChangeNotificationNew(
    val location: Double,
    val peerLocations: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPLocationChangeNotification2"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPRoutedPing(
    val uid: Long,
    val targetLocation: Double,
    val htl: Short,
    val counter: Int,
    val nodeIdentity: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPRoutedPing"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPRoutedPong(
    val uid: Long,
    val counter: Int,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPRoutedPong"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPRoutedRejected(
    val uid: Long,
    val htl: Short,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPRoutedRejected"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPDetectedIPAddress(val externalAddress: ByteArray) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPDetectedIPAddress"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPTime(val time: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPTime"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPUptime(val uptimePercent48h: Byte) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPUptime"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPVisibility(val friendVisibility: Short) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPVisibility"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSentPackets(
    val timeDeltas: ByteArray,
    val hashes: ByteArray,
    val time: Long,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSentPackets"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPVoid : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPVoid"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = true
    }
}

@Serializable
class FNPDisconnect(
    val remove: Boolean,
    val purge: Boolean,
    val nodeToNodeMessageType: Int,
    val nodeToNodeMessageData: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPDisconnect"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class UOMAnnouncement(
    val mainJarKey: String,
    val revocationKey: String,
    val haveRevocationKey: Boolean,
    val mainJarVersion: Long,
    val revocationKeyTimeLastTried: Long,
    val revocationKeyDNFCount: Int,
    val revocationKeyFileLength: Long,
    val mainJarFileLength: Long,
    val pingTime: Int,
    val bwlimitDelayTime: Int,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "UOMAnnouncement"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class UOMRequestRevocation(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "UOMRequestRevocation"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class UOMRequestMainJar(val uid: Long) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "UOMRequestMainJar"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class UOMSendingRevocation(
    val uid: Long,
    val fileLength: Long,
    val revocationKey: String,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "UOMSendingRevocation"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class UOMSendingMainJar(
    val uid: Long,
    val fileLength: Long,
    val mainJarKey: String,
    val mainJarVersion: Int,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "UOMSendingMainJar"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class UOMFetchDependency(
    val uid: Long,
    val expectedHash: ByteArray,
    val fileLength: Long,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "UOMFetchDependency"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSwapNodeUIDs(val nodeUids: ByteArray) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSwapNodeUIDs"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPBestRoutesNotTaken(val bestLocationsNotVisited: ByteArray) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPBestRoutesNotTaken"
        override val priority = Priority.UNSPECIFIED
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPRoutingStatus(val routingEnabled: Boolean) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPRoutingStatus"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSubInsertForkControl(val enableInsertForkWhenCacheable: Boolean) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSubInsertForkControl"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSubInsertPreferInsert(val preferInsert: Boolean) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSubInsertPreferInsert"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPSubInsertIgnoreLowBackoff(val ignoreLowBackoff: Boolean) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPSubInsertIgnoreLowBackoff"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPRejectIsSoft : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPRejectIsSoft"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPPeerLoadStatusByte(
    val otherTransfersOutCHK: Byte,
    val otherTransfersInCHK: Byte,
    val otherTransfersOutSSK: Byte,
    val otherTransfersInSSK: Byte,
    val averageTransfersOutPerInsert: Byte,
    val outputBandwidthLowerLimit: Int,
    val outputBandwidthUpperLimit: Int,
    val outputBandwidthPeerLimit: Int,
    val inputBandwidthLowerLimit: Int,
    val inputBandwidthUpperLimit: Int,
    val inputBandwidthPeerLimit: Int,
    val maxTransfersOut: Byte,
    val maxTransfersOutPeerLimit: Byte,
    val maxTransfersOutLowerLimit: Byte,
    val maxTransfersOutUpperLimit: Byte,
    val realTimeFlag: Boolean,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPPeerLoadStatusByte"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = true
    }
}

@Serializable
class FNPPeerLoadStatusShort(
    val otherTransfersOutCHK: Short,
    val otherTransfersInCHK: Short,
    val otherTransfersOutSSK: Short,
    val otherTransfersInSSK: Short,
    val averageTransfersOutPerInsert: Short,
    val outputBandwidthLowerLimit: Int,
    val outputBandwidthUpperLimit: Int,
    val outputBandwidthPeerLimit: Int,
    val inputBandwidthLowerLimit: Int,
    val inputBandwidthUpperLimit: Int,
    val inputBandwidthPeerLimit: Int,
    val maxTransfersOut: Short,
    val maxTransfersOutPeerLimit: Short,
    val maxTransfersOutLowerLimit: Short,
    val maxTransfersOutUpperLimit: Short,
    val realTimeFlag: Boolean,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPPeerLoadStatusShort"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = true
    }
}

@Serializable
class FNPPeerLoadStatusInt(
    val otherTransfersOutCHK: Int,
    val otherTransfersInCHK: Int,
    val otherTransfersOutSSK: Int,
    val otherTransfersInSSK: Int,
    val averageTransfersOutPerInsert: Int,
    val outputBandwidthLowerLimit: Int,
    val outputBandwidthUpperLimit: Int,
    val outputBandwidthPeerLimit: Int,
    val inputBandwidthLowerLimit: Int,
    val inputBandwidthUpperLimit: Int,
    val inputBandwidthPeerLimit: Int,
    val maxTransfersOut: Int,
    val maxTransfersOutPeerLimit: Int,
    val maxTransfersOutLowerLimit: Int,
    val maxTransfersOutUpperLimit: Int,
    val realTimeFlag: Boolean,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPPeerLoadStatusInt"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = true
    }
}

@Serializable
class FNPRealTimeFlag(val realTimeFlag: Boolean) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPRealTimeFlag"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPCheckStillRunning(
    val uid: Long,
    val listOfUids: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPCheckStillRunning"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPIsStillRunning(
    val uid: Long,
    val uidStillRunningFlags: ByteArray,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPIsStillRunning"
        override val priority = Priority.HIGH
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPGetYourFullNoderef : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPGetYourFullNoderef"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

@Serializable
class FNPMyFullNoderef(
    val uid: Long,
    val noderefLength: Int,
) : MessageType {
    @Transient
    override val metaData: MessageTypeMetaData = object : MessageTypeMetaData {
        override val messageTypeName = "FNPMyFullNoderef"
        override val priority = Priority.LOW
        override val isLossyPacketMessage = false
    }
}

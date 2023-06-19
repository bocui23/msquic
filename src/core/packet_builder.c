/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Packet builder abstracts the logic to build up a chain of UDP datagrams each
    of which may consist of multiple QUIC packets. As necessary, it allocates
    additional datagrams, adds QUIC packet headers, finalizes the QUIC packet
    encryption and sends the packets off.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "packet_builder.c.clog.h"
#endif
#include "picotls.h"
#include "picotls/fusion.h"
#include "intel-ipsec-mb.h"

#ifdef QUIC_FUZZER

__declspec(noinline)
void
QuicFuzzInjectHook(
    _Inout_ QUIC_PACKET_BUILDER *Builder
    );

#endif


_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPacketBuilderCryptoBatch(
    _Inout_ QUIC_PACKET_BUILDER *Builder
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPacketBuilderSendBatch(
    _Inout_ QUIC_PACKET_BUILDER* Builder
    );

#if DEBUG
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPacketBuilderValidate(
    _In_ const QUIC_PACKET_BUILDER* Builder,
    _In_ BOOLEAN ShouldHaveData
    )
{
    if (ShouldHaveData) {
        CXPLAT_DBG_ASSERT(Builder->Key != NULL);
        CXPLAT_DBG_ASSERT(Builder->SendData != NULL);
        CXPLAT_DBG_ASSERT(Builder->Datagram != NULL);
        CXPLAT_DBG_ASSERT(Builder->DatagramLength != 0);
        CXPLAT_DBG_ASSERT(Builder->HeaderLength != 0);
        CXPLAT_DBG_ASSERT(Builder->Metadata->FrameCount != 0);
    }

    CXPLAT_DBG_ASSERT(Builder->Path != NULL);
    CXPLAT_DBG_ASSERT(Builder->Path->DestCid != NULL);
    CXPLAT_DBG_ASSERT(Builder->BatchCount <= QUIC_MAX_CRYPTO_BATCH_COUNT);

    if (Builder->Key != NULL) {
        CXPLAT_DBG_ASSERT(Builder->Key->PacketKey != NULL);
        CXPLAT_DBG_ASSERT(Builder->Key->HeaderKey != NULL);
    }

    CXPLAT_DBG_ASSERT(Builder->EncryptionOverhead <= 16);
    if (Builder->SendData == NULL) {
        CXPLAT_DBG_ASSERT(Builder->Datagram == NULL);
    }

    if (Builder->Datagram) {
        CXPLAT_DBG_ASSERT(Builder->Datagram->Length != 0);
        CXPLAT_DBG_ASSERT(Builder->Datagram->Length <= UINT16_MAX);
        CXPLAT_DBG_ASSERT(Builder->Datagram->Length >= Builder->MinimumDatagramLength);
        CXPLAT_DBG_ASSERT(Builder->Datagram->Length >= (uint32_t)(Builder->DatagramLength + Builder->EncryptionOverhead));
        CXPLAT_DBG_ASSERT(Builder->DatagramLength >= Builder->PacketStart);
        CXPLAT_DBG_ASSERT(Builder->DatagramLength >= Builder->HeaderLength);
        CXPLAT_DBG_ASSERT(Builder->DatagramLength >= Builder->PacketStart + Builder->HeaderLength);
        if (Builder->PacketType != SEND_PACKET_SHORT_HEADER_TYPE) {
            CXPLAT_DBG_ASSERT(Builder->PayloadLengthOffset != 0);
            if (ShouldHaveData) {
                CXPLAT_DBG_ASSERT(Builder->DatagramLength >= Builder->PacketStart + Builder->PayloadLengthOffset);
            }
        }
    } else {
        CXPLAT_DBG_ASSERT(Builder->DatagramLength == 0);
        CXPLAT_DBG_ASSERT(Builder->Metadata->FrameCount == 0);
    }
}
#else
#define QuicPacketBuilderValidate(Builder, ShouldHaveData) // no-op
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderInitialize(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    CXPLAT_DBG_ASSERT(Path->DestCid != NULL);
    Builder->Connection = Connection;
    Builder->Path = Path;
    Builder->PacketBatchSent = FALSE;
    Builder->PacketBatchRetransmittable = FALSE;
    Builder->Metadata = &Builder->MetadataStorage.Metadata;
    Builder->EncryptionOverhead = CXPLAT_ENCRYPTION_OVERHEAD;
    Builder->TotalDatagramsLength = 0;

    if (Connection->SourceCids.Next == NULL) {
        QuicTraceLogConnWarning(
            NoSrcCidAvailable,
            Connection,
            "No src CID to send with");
        return FALSE;
    }

    Builder->SourceCid =
        CXPLAT_CONTAINING_RECORD(
            Connection->SourceCids.Next,
            QUIC_CID_HASH_ENTRY,
            Link);

    uint64_t TimeNow = CxPlatTimeUs64();
    uint64_t TimeSinceLastSend;
    if (Connection->Send.LastFlushTimeValid) {
        TimeSinceLastSend =
            CxPlatTimeDiff64(Connection->Send.LastFlushTime, TimeNow);
    } else {
        TimeSinceLastSend = 0;
    }
    Builder->SendAllowance =
        QuicCongestionControlGetSendAllowance(
            &Connection->CongestionControl,
            TimeSinceLastSend,
            Connection->Send.LastFlushTimeValid);
    if (Builder->SendAllowance > Path->Allowance) {
        Builder->SendAllowance = Path->Allowance;
    }
    Connection->Send.LastFlushTime = TimeNow;
    Connection->Send.LastFlushTimeValid = TRUE;

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPacketBuilderCleanup(
    _Inout_ QUIC_PACKET_BUILDER* Builder
    )
{
    CXPLAT_DBG_ASSERT(Builder->SendData == NULL);

    if (Builder->PacketBatchSent && Builder->PacketBatchRetransmittable) {
        QuicLossDetectionUpdateTimer(&Builder->Connection->LossDetection, FALSE);
    }

    QuicSentPacketMetadataReleaseFrames(Builder->Metadata);

    CxPlatSecureZeroMemory(Builder->HpMask, sizeof(Builder->HpMask));
}

//
// This function makes sure the current send buffer and other related data is
// prepared for writing the requested data. If there was already a QUIC packet
// in the process of being built, it will try to reuse it if possible. If not,
// it will finalize the current one and start a new one.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderPrepare(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ QUIC_PACKET_KEY_TYPE NewPacketKeyType,
    _In_ BOOLEAN IsTailLossProbe,
    _In_ BOOLEAN IsPathMtuDiscovery
    )
{
    QUIC_CONNECTION* Connection = Builder->Connection;
    if (Connection->Crypto.TlsState.WriteKeys[NewPacketKeyType] == NULL) {
        //
        // A NULL key here usually means the connection had a fatal error in
        // such a way that resulted in the key not getting created. The
        // connection is most likely trying to send a connection close frame,
        // but without the key, nothing can be done. Just silently kill the
        // connection.
        //
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "NULL key in builder prepare");
        QuicConnSilentlyAbort(Connection);
        return FALSE;
    }

    BOOLEAN Result = FALSE;
    uint8_t NewPacketType =
        Connection->Stats.QuicVersion == QUIC_VERSION_2 ?
            QuicKeyTypeToPacketTypeV2(NewPacketKeyType) :
            QuicKeyTypeToPacketTypeV1(NewPacketKeyType);

    //
    // For now, we can't send QUIC Bit as 0 on initial packets from client to server.
    // see: https://www.ietf.org/archive/id/draft-ietf-quic-bit-grease-04.html#name-clearing-the-quic-bit
    //
    BOOLEAN FixedBit = (QuicConnIsClient(Connection) &&
        (NewPacketType == (uint8_t)QUIC_INITIAL_V1 || NewPacketKeyType == (uint8_t)QUIC_INITIAL_V2)) ? TRUE : Connection->State.FixedBit;

    uint16_t DatagramSize = Builder->Path->Mtu;
    if ((uint32_t)DatagramSize > Builder->Path->Allowance) {
        CXPLAT_DBG_ASSERT(!IsPathMtuDiscovery); // PMTUD always happens after source addr validation.
        DatagramSize = (uint16_t)Builder->Path->Allowance;
    }
    CXPLAT_DBG_ASSERT(!IsPathMtuDiscovery || !IsTailLossProbe); // Never both.
    QuicPacketBuilderValidate(Builder, FALSE);

    //
    // Next, make sure the current QUIC packet matches the new packet type. If
    // the current one doesn't match, finalize it and then start a new one.
    //

    uint32_t Proc = CxPlatProcCurrentNumber();
    uint64_t ProcShifted = ((uint64_t)Proc + 1) << 40;

    BOOLEAN NewQuicPacket = FALSE;
    if (Builder->PacketType != NewPacketType || IsPathMtuDiscovery ||
        (Builder->Datagram != NULL && (Builder->Datagram->Length - Builder->DatagramLength) < QUIC_MIN_PACKET_SPARE_SPACE)) {
        //
        // The current data cannot go in the current QUIC packet. Finalize the
        // current QUIC packet up so we can create another.
        //
        if (Builder->SendData != NULL) {
            BOOLEAN FlushDatagrams = IsPathMtuDiscovery;
            if (Builder->PacketType != NewPacketType &&
                Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE) {
                FlushDatagrams = TRUE;
            }
            QuicPacketBuilderFinalize(Builder, FlushDatagrams);
        }
        if (Builder->SendData == NULL &&
            Builder->TotalCountDatagrams >= QUIC_MAX_DATAGRAMS_PER_SEND) {
            goto Error;
        }
        NewQuicPacket = TRUE;

    } else if (Builder->Datagram == NULL) {
        NewQuicPacket = TRUE;
    }

    if (Builder->Datagram == NULL) {

        //
        // Allocate and initialize a new send buffer (UDP packet/payload).
        //
        BOOLEAN SendDataAllocated = FALSE;
        if (Builder->SendData == NULL) {
            Builder->BatchId =
                ProcShifted | InterlockedIncrement64((int64_t*)&MsQuicLib.PerProc[Proc].SendBatchId);
            CXPLAT_SEND_CONFIG SendConfig = {
                &Builder->Path->Route,
                IsPathMtuDiscovery ?
                    0 :
                    MaxUdpPayloadSizeForFamily(
                        QuicAddrGetFamily(&Builder->Path->Route.RemoteAddress),
                        DatagramSize),
                Builder->EcnEctSet ? CXPLAT_ECN_ECT_0 : CXPLAT_ECN_NON_ECT,
                Builder->Connection->Registration->ExecProfile == QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT ?
                    CXPLAT_SEND_FLAGS_MAX_THROUGHPUT : CXPLAT_SEND_FLAGS_NONE
            };
            Builder->SendData =
                CxPlatSendDataAlloc(Builder->Path->Binding->Socket, &SendConfig);
            if (Builder->SendData == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "packet send context",
                    0);
                goto Error;
            }
            SendDataAllocated = TRUE;
        }

        uint16_t NewDatagramLength =
            MaxUdpPayloadSizeForFamily(
                QuicAddrGetFamily(&Builder->Path->Route.RemoteAddress),
                IsPathMtuDiscovery ? Builder->Path->MtuDiscovery.ProbeSize : DatagramSize);
        if ((Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE) &&
            NewDatagramLength > Connection->PeerTransportParams.MaxUdpPayloadSize) {
            NewDatagramLength = (uint16_t)Connection->PeerTransportParams.MaxUdpPayloadSize;
        }

        Builder->Datagram =
            CxPlatSendDataAllocBuffer(
                Builder->SendData,
                NewDatagramLength);
        if (Builder->Datagram == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "packet datagram",
                NewDatagramLength);
            if (SendDataAllocated) {
                CxPlatSendDataFree(Builder->SendData);
                Builder->SendData = NULL;
            }
            goto Error;
        }

        Builder->DatagramLength = 0;
        Builder->MinimumDatagramLength = 0;

        if (IsTailLossProbe && QuicConnIsClient(Connection)) {
            if (NewPacketType == SEND_PACKET_SHORT_HEADER_TYPE) {
                //
                // Short header (1-RTT) packets need to be padded enough to
                // elicit stateless resets from the server.
                //
                Builder->MinimumDatagramLength =
                    QUIC_RECOMMENDED_STATELESS_RESET_PACKET_LENGTH +
                    8 /* a little fudge factor */;
            } else {
                //
                // Initial/Handshake packets need to be padded to unblock a
                // server (possibly) blocked on source address validation.
                //
                Builder->MinimumDatagramLength = NewDatagramLength;
            }

        } else if ((Connection->Stats.QuicVersion == QUIC_VERSION_2 && NewPacketType == QUIC_INITIAL_V2) ||
            (Connection->Stats.QuicVersion != QUIC_VERSION_2 && NewPacketType == QUIC_INITIAL_V1)) {

            //
            // Make sure to pad Initial packets.
            //
            Builder->MinimumDatagramLength =
                MaxUdpPayloadSizeForFamily(
                    QuicAddrGetFamily(&Builder->Path->Route.RemoteAddress),
                    Builder->Path->Mtu);

            if ((uint32_t)Builder->MinimumDatagramLength > Builder->Datagram->Length) {
                //
                // On server, if we're limited by amplification protection, just
                // pad up to that limit instead.
                //
                Builder->MinimumDatagramLength = (uint16_t)Builder->Datagram->Length;
            }

        } else if (IsPathMtuDiscovery) {
            Builder->MinimumDatagramLength = NewDatagramLength;
        }
    }

    if (NewQuicPacket) {

        //
        // Initialize the new QUIC packet state.
        //

        Builder->PacketType = NewPacketType;
        Builder->EncryptLevel =
            Connection->Stats.QuicVersion == QUIC_VERSION_2 ?
                QuicPacketTypeToEncryptLevelV2(NewPacketType) :
                QuicPacketTypeToEncryptLevelV1(NewPacketType);
        Builder->Key = Connection->Crypto.TlsState.WriteKeys[NewPacketKeyType];
        CXPLAT_DBG_ASSERT(Builder->Key != NULL);
        CXPLAT_DBG_ASSERT(Builder->Key->PacketKey != NULL);
        CXPLAT_DBG_ASSERT(Builder->Key->HeaderKey != NULL);
        if (NewPacketKeyType == QUIC_PACKET_KEY_1_RTT &&
            Connection->State.Disable1RttEncrytion) {
            Builder->EncryptionOverhead = 0;
        }

        Builder->Metadata->PacketId =
            ProcShifted | InterlockedIncrement64((int64_t*)&MsQuicLib.PerProc[Proc].SendPacketId);
        QuicTraceEvent(
            PacketCreated,
            "[pack][%llu] Created in batch %llu",
            Builder->Metadata->PacketId,
            Builder->BatchId);

        Builder->Metadata->FrameCount = 0;
        Builder->Metadata->PacketNumber = Connection->Send.NextPacketNumber++;
        Builder->Metadata->Flags.KeyType = NewPacketKeyType;
        Builder->Metadata->Flags.IsAckEliciting = FALSE;
        Builder->Metadata->Flags.IsMtuProbe = IsPathMtuDiscovery;
        Builder->Metadata->Flags.SuspectedLost = FALSE;
#if DEBUG
        Builder->Metadata->Flags.Freed = FALSE;
#endif

        Builder->PacketStart = Builder->DatagramLength;
        Builder->HeaderLength = 0;

        uint8_t* Header =
            Builder->Datagram->Buffer + Builder->DatagramLength;
        uint16_t BufferSpaceAvailable =
            (uint16_t)Builder->Datagram->Length - Builder->DatagramLength;

        if (NewPacketType == SEND_PACKET_SHORT_HEADER_TYPE) {
            QUIC_PACKET_SPACE* PacketSpace = Connection->Packets[Builder->EncryptLevel];

            Builder->PacketNumberLength = 4; // TODO - Determine correct length based on BDP.

            switch (Connection->Stats.QuicVersion) {
            case QUIC_VERSION_1:
            case QUIC_VERSION_DRAFT_29:
            case QUIC_VERSION_MS_1:
            case QUIC_VERSION_2:
                Builder->HeaderLength =
                    QuicPacketEncodeShortHeaderV1(
                        &Builder->Path->DestCid->CID,
                        Builder->Metadata->PacketNumber,
                        Builder->PacketNumberLength,
                        Builder->Path->SpinBit,
                        PacketSpace->CurrentKeyPhase,
                        FixedBit,
                        BufferSpaceAvailable,
                        Header);
                Builder->Metadata->Flags.KeyPhase = PacketSpace->CurrentKeyPhase;
                break;
            default:
                CXPLAT_FRE_ASSERT(FALSE);
                Builder->HeaderLength = 0; // For build warning.
                break;
            }

        } else { // Long Header

            switch (Connection->Stats.QuicVersion) {
            case QUIC_VERSION_1:
            case QUIC_VERSION_DRAFT_29:
            case QUIC_VERSION_MS_1:
            case QUIC_VERSION_2:
            default:
                Builder->HeaderLength =
                    QuicPacketEncodeLongHeaderV1(
                        Connection->Stats.QuicVersion,
                        NewPacketType,
                        FixedBit,
                        &Builder->Path->DestCid->CID,
                        &Builder->SourceCid->CID,
                        Connection->Send.InitialTokenLength,
                        Connection->Send.InitialToken,
                        (uint32_t)Builder->Metadata->PacketNumber,
                        BufferSpaceAvailable,
                        Header,
                        &Builder->PayloadLengthOffset,
                        &Builder->PacketNumberLength);
                break;
            }
        }

        Builder->DatagramLength += Builder->HeaderLength;
    }

    CXPLAT_DBG_ASSERT(Builder->PacketType == NewPacketType);
    CXPLAT_DBG_ASSERT(Builder->Key == Connection->Crypto.TlsState.WriteKeys[NewPacketKeyType]);
    CXPLAT_DBG_ASSERT(Builder->BatchCount == 0 || Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE);

    Result = TRUE;

Error:

    QuicPacketBuilderValidate(Builder, FALSE);

    return Result;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderGetPacketTypeAndKeyForControlFrames(
    _In_ const QUIC_PACKET_BUILDER* Builder,
    _In_ uint32_t SendFlags,
    _Out_ QUIC_PACKET_KEY_TYPE* PacketKeyType
    )
{
    QUIC_CONNECTION* Connection = Builder->Connection;

    CXPLAT_DBG_ASSERT(SendFlags != 0);
    QuicSendValidate(&Builder->Connection->Send);

    for (QUIC_PACKET_KEY_TYPE KeyType = 0;
         KeyType <= Connection->Crypto.TlsState.WriteKey;
         ++KeyType) {

        if (KeyType == QUIC_PACKET_KEY_0_RTT) {
            continue; // Crypto is never written with 0-RTT key.
        }

        QUIC_PACKET_KEY* PacketsKey =
            Connection->Crypto.TlsState.WriteKeys[KeyType];
        if (PacketsKey == NULL) {
            continue; // Key has been discarded.
        }

        QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(KeyType);
        if (EncryptLevel == QUIC_ENCRYPT_LEVEL_1_RTT) {
            //
            // Always allowed to send with 1-RTT.
            //
            *PacketKeyType = QUIC_PACKET_KEY_1_RTT;
            return TRUE;
        }

        QUIC_PACKET_SPACE* Packets = Connection->Packets[EncryptLevel];
        CXPLAT_DBG_ASSERT(Packets != NULL);

        if (SendFlags & QUIC_CONN_SEND_FLAG_ACK &&
            Packets->AckTracker.AckElicitingPacketsToAcknowledge) {
            //
            // ACK frames have the highest send priority; but they only
            // determine a packet type if they can be sent as ACK-only.
            //
            *PacketKeyType = KeyType;
            return TRUE;
        }

        if (SendFlags & QUIC_CONN_SEND_FLAG_CRYPTO &&
            QuicCryptoHasPendingCryptoFrame(&Connection->Crypto) &&
            EncryptLevel == QuicCryptoGetNextEncryptLevel(&Connection->Crypto)) {
            //
            // Crypto handshake data is ready to be sent.
            //
            *PacketKeyType = KeyType;
            return TRUE;
        }
    }

    if (SendFlags & (QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE | QUIC_CONN_SEND_FLAG_PING)) {
        //
        // CLOSE or PING is ready to be sent. This is always sent with the
        // current write key.
        //
        // TODO - This logic isn't correct. The peer might not be able to read
        // this key, so the CLOSE frame should be sent at the current and
        // previous encryption level if the handshake hasn't been confirmed.
        //
        if (Connection->Crypto.TlsState.WriteKey == QUIC_PACKET_KEY_0_RTT) {
            *PacketKeyType = QUIC_PACKET_KEY_INITIAL;
        } else {
            *PacketKeyType = Connection->Crypto.TlsState.WriteKey;
        }
        return TRUE;
    }

    if (Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT] != NULL) {
        *PacketKeyType = QUIC_PACKET_KEY_1_RTT;
        return TRUE;
    }

    QuicTraceLogConnWarning(
        GetPacketTypeFailure,
        Builder->Connection,
        "Failed to get packet type for control frames, 0x%x",
        SendFlags);
    CXPLAT_DBG_ASSERT(CxPlatIsRandomMemoryFailureEnabled()); // This shouldn't have been called then!

    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderPrepareForControlFrames(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ BOOLEAN IsTailLossProbe,
    _In_ uint32_t SendFlags
    )
{
    CXPLAT_DBG_ASSERT(!(SendFlags & QUIC_CONN_SEND_FLAG_DPLPMTUD));
    QUIC_PACKET_KEY_TYPE PacketKeyType;
    return
        QuicPacketBuilderGetPacketTypeAndKeyForControlFrames(
            Builder,
            SendFlags,
            &PacketKeyType) &&
        QuicPacketBuilderPrepare(
            Builder,
            PacketKeyType,
            IsTailLossProbe,
            FALSE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderPrepareForPathMtuDiscovery(
    _Inout_ QUIC_PACKET_BUILDER* Builder
    )
{
    return
        QuicPacketBuilderPrepare(
            Builder,
            QUIC_PACKET_KEY_1_RTT,
            FALSE,
            TRUE);
}


_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketBuilderPrepareForStreamFrames(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ BOOLEAN IsTailLossProbe
    )
{
    QUIC_PACKET_KEY_TYPE PacketKeyType;

    if (Builder->Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_0_RTT] != NULL &&
        Builder->Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT] == NULL) {
        //
        // Application stream data can only be sent with the 0-RTT key if the
        // 1-RTT key is unavailable.
        //
        PacketKeyType = QUIC_PACKET_KEY_0_RTT;

    } else {
        CXPLAT_DBG_ASSERT(Builder->Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT]);
        PacketKeyType = QUIC_PACKET_KEY_1_RTT;
    }

    return QuicPacketBuilderPrepare(Builder, PacketKeyType, IsTailLossProbe, FALSE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPacketBuilderFinalizeHeaderProtection(
    _Inout_ QUIC_PACKET_BUILDER* Builder
    )
{
    CXPLAT_DBG_ASSERT(Builder->Key != NULL);

#ifndef QUIC_BYPASS_HP
    QUIC_STATUS Status;
    if (QUIC_FAILED(
        Status =
        CxPlatHpComputeMask(
            Builder->Key->HeaderKey,
            Builder->BatchCount,
            Builder->CipherBatch,
            Builder->HpMask))) {
        CXPLAT_TEL_ASSERT(FALSE);
        QuicConnFatalError(Builder->Connection, Status, "HP failure");
        return;
    }
#else
    CxPlatCopyMemory(Builder->HpMask, Builder->CipherBatch, Builder->BatchCount * CXPLAT_HP_SAMPLE_LENGTH);
#endif

    for (uint8_t i = 0; i < Builder->BatchCount; ++i) {
        uint16_t Offset = i * CXPLAT_HP_SAMPLE_LENGTH;
        uint8_t* Header = Builder->HeaderBatch[i];
        Header[0] ^= (Builder->HpMask[Offset] & 0x1f); // Bottom 5 bits for SH
        Header += 1 + Builder->Path->DestCid->CID.Length;
        for (uint8_t j = 0; j < Builder->PacketNumberLength; ++j) {
            Header[j] ^= Builder->HpMask[Offset + 1 + j];
        }
    }

    Builder->BatchCount = 0;
}

//
// This function completes the current QUIC packet. It updates the header if
// necessary and encrypts the payload. If there isn't enough space for another
// QUIC packet, it also completes the send buffer (i.e. UDP payload) and sets
// the current send buffer pointer to NULL. If that send buffer was the last
// in the current send batch, then the send context is also completed and sent
// off.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPacketBuilderFinalize(
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ BOOLEAN FlushBatchedDatagrams
    )
{
    QUIC_CONNECTION* Connection = Builder->Connection;
    BOOLEAN FinalQuicPacket = FALSE;
    BOOLEAN CanKeepSending = TRUE;

    QuicPacketBuilderValidate(Builder, FALSE);

    if (Builder->Datagram == NULL || Builder->Metadata->FrameCount == 0) {
        //
        // Nothing got framed into this packet. Undo the header of this
        // packet.
        //
        if (Builder->Datagram != NULL) {
            --Connection->Send.NextPacketNumber;
            Builder->DatagramLength -= Builder->HeaderLength;
            Builder->HeaderLength = 0;
            CanKeepSending = FALSE;

            if (Builder->DatagramLength == 0) {
                CxPlatSendDataFreeBuffer(Builder->SendData, Builder->Datagram);
                Builder->Datagram = NULL;
            }
        }
        if (Builder->Path->Allowance != UINT32_MAX) {
            QuicConnAddOutFlowBlockedReason(
                Connection, QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT);
        }
        FinalQuicPacket = FlushBatchedDatagrams && (Builder->TotalCountDatagrams != 0);
        goto Exit;
    }

    QuicPacketBuilderValidate(Builder, TRUE);

    //
    // Calculate some of the packet buffer parameters (mostly used for encryption).
    //
    uint8_t* Header =
        Builder->Datagram->Buffer + Builder->PacketStart;
    uint16_t PayloadLength =
        Builder->DatagramLength - (Builder->PacketStart + Builder->HeaderLength);
    uint16_t ExpectedFinalDatagramLength =
        Builder->DatagramLength + Builder->EncryptionOverhead;

    if (FlushBatchedDatagrams ||
        Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE ||
        (uint16_t)Builder->Datagram->Length - ExpectedFinalDatagramLength < QUIC_MIN_PACKET_SPARE_SPACE) {

        FinalQuicPacket = TRUE;

        if (!FlushBatchedDatagrams && CxPlatDataPathIsPaddingPreferred(MsQuicLib.Datapath)) {
            //
            // When buffering multiple datagrams in a single contiguous buffer
            // (at the datapath layer), all but the last datagram needs to be
            // fully padded.
            //
            Builder->MinimumDatagramLength = (uint16_t)Builder->Datagram->Length;
        }
    }

    uint16_t PaddingLength;
    if (FinalQuicPacket && ExpectedFinalDatagramLength < Builder->MinimumDatagramLength) {
        PaddingLength = Builder->MinimumDatagramLength - ExpectedFinalDatagramLength;
    } else if (Builder->PacketNumberLength + PayloadLength < sizeof(uint32_t)) {
        //
        // For packet protection to work, there must always be at least 4 bytes
        // of payload and/or packet number.
        //
        PaddingLength = sizeof(uint32_t) - Builder->PacketNumberLength - PayloadLength;
    } else {
        PaddingLength = 0;
    }

    if (PaddingLength != 0) {
        CxPlatZeroMemory(
            Builder->Datagram->Buffer + Builder->DatagramLength,
            PaddingLength);
        PayloadLength += PaddingLength;
        Builder->DatagramLength += PaddingLength;
    }

    if (Builder->PacketType != SEND_PACKET_SHORT_HEADER_TYPE) {
        switch (Connection->Stats.QuicVersion) {
        case QUIC_VERSION_1:
        case QUIC_VERSION_DRAFT_29:
        case QUIC_VERSION_MS_1:
        case QUIC_VERSION_2:
        default:
            QuicVarIntEncode2Bytes(
                (uint16_t)Builder->PacketNumberLength +
                    PayloadLength +
                    Builder->EncryptionOverhead,
                Header + Builder->PayloadLengthOffset);
            break;
        }
    }

#ifdef QUIC_FUZZER
    QuicFuzzInjectHook(Builder);
#endif

    if (QuicTraceLogVerboseEnabled()) {
        QuicPacketLogHeader(
            Connection,
            FALSE,
            Builder->Path->DestCid->CID.Length,
            Builder->Metadata->PacketNumber,
            Builder->HeaderLength + PayloadLength,
            Header,
            Connection->Stats.QuicVersion);
        QuicFrameLogAll(
            Connection,
            FALSE,
            Builder->Metadata->PacketNumber,
            Builder->HeaderLength + PayloadLength,
            Header,
            Builder->HeaderLength);
    }

    if (Builder->EncryptionOverhead != 0) {

        //
        // Encrypt the data.
        //

        QuicTraceEvent(
            PacketEncrypt,
            "[pack][%llu] Encrypting",
            Builder->Metadata->PacketId);

        PayloadLength += Builder->EncryptionOverhead;
        Builder->DatagramLength += Builder->EncryptionOverhead;

        uint8_t* Payload = Header + Builder->HeaderLength;

        uint8_t Iv[CXPLAT_MAX_IV_LENGTH];
        QuicCryptoCombineIvAndPacketNumber(Builder->Key->Iv, (uint8_t*) &Builder->Metadata->PacketNumber, Iv);

        QUIC_STATUS Status;


#ifdef QUIC_BATCH_CRYPTO_HP
        // stash 1-rtt packets into a batch crypto, valid for short header type only
        if (Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE)
        {
            uint32_t BatchIdx = Builder->BCQuicAmount++;
            Builder->BCQuicHdr[BatchIdx] = Header;
            Builder->BCQuicPayload[BatchIdx] = Payload;
            Builder->BCQuicPayloadLength[BatchIdx] = PayloadLength;
            Builder->BCQuicSN[BatchIdx] = Builder->Metadata->PacketNumber;
            CxPlatCopyMemory (Builder->BCQuicIV + CXPLAT_MAX_IV_LENGTH * BatchIdx, Iv, CXPLAT_MAX_IV_LENGTH);
        }
        else
#endif
        {
#ifndef QUIC_BYPASS_CRYPTO
            if (QUIC_FAILED(
                Status =
                CxPlatEncrypt(
                    Builder->Key->PacketKey,
                    Iv,
                    Builder->HeaderLength,
                    Header,
                    PayloadLength,
                    Payload))) {
                QuicConnFatalError(Connection, Status, "Encryption failure");
                goto Exit;
            }
#endif
        }

        QuicTraceEvent(
            PacketFinalize,
            "[pack][%llu] Finalizing",
            Builder->Metadata->PacketId);

        if (Connection->State.HeaderProtectionEnabled) {

            uint8_t* PnStart = Payload - Builder->PacketNumberLength;

            if (Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE)
#ifndef QUIC_BATCH_CRYPTO_HP
            {
                CXPLAT_DBG_ASSERT(Builder->BatchCount < QUIC_MAX_CRYPTO_BATCH_COUNT);

                //
                // Batch the header protection for short header packets.
                //

                CxPlatCopyMemory(
                    Builder->CipherBatch + Builder->BatchCount * CXPLAT_HP_SAMPLE_LENGTH,
                    PnStart + 4,
                    CXPLAT_HP_SAMPLE_LENGTH);
                Builder->HeaderBatch[Builder->BatchCount] = Header;

                if (++Builder->BatchCount == QUIC_MAX_CRYPTO_BATCH_COUNT) {
                    QuicPacketBuilderFinalizeHeaderProtection(Builder);
                }
            }
#else
            {
                // do nothing as short header protection will be done in an async batch
            }
#endif
            else
            {
                CXPLAT_DBG_ASSERT(Builder->BatchCount == 0);

                //
                // Individually do header protection for long header packets as
                // they generally use different keys.
                //
#ifndef QUIC_BYPASS_HP
                if (QUIC_FAILED(
                    Status =
                    CxPlatHpComputeMask(
                        Builder->Key->HeaderKey,
                        1,
                        PnStart + 4,
                        Builder->HpMask))) {
                    CXPLAT_TEL_ASSERT(FALSE);
                    QuicConnFatalError(Connection, Status, "HP failure");
                    goto Exit;
                }
#else
                CxPlatCopyMemory(Builder->HpMask, PnStart + 4, CXPLAT_HP_SAMPLE_LENGTH);
#endif

                Header[0] ^= (Builder->HpMask[0] & 0x0f); // Bottom 4 bits for LH
                for (uint8_t i = 0; i < Builder->PacketNumberLength; ++i) {
                    PnStart[i] ^= Builder->HpMask[1 + i];
                }
            }
        }

        //
        // Increment the key phase sent bytes count.
        //
        QUIC_PACKET_SPACE* PacketSpace = Connection->Packets[Builder->EncryptLevel];
        PacketSpace->CurrentKeyPhaseBytesSent += (PayloadLength - Builder->EncryptionOverhead);

        //
        // Check if the next packet sent will exceed the limit of bytes per
        // key phase, and update the keys. Only for 1-RTT keys.
        //
        if (Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE &&
            PacketSpace->CurrentKeyPhaseBytesSent + CXPLAT_MAX_MTU >=
                Connection->Settings.MaxBytesPerKey &&
            !PacketSpace->AwaitingKeyPhaseConfirmation &&
            Connection->State.HandshakeConfirmed) {

            Status = QuicCryptoGenerateNewKeys(Connection);
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    Status,
                    "Send-triggered key update");
                QuicConnFatalError(Connection, Status, "Send-triggered key update");
                goto Exit;
            }

            QuicCryptoUpdateKeyPhase(Connection, TRUE);

            //
            // Update the packet key in use by the send builder.
            //
            Builder->Key = Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT];
            CXPLAT_DBG_ASSERT(Builder->Key != NULL);
            CXPLAT_DBG_ASSERT(Builder->Key->PacketKey != NULL);
            CXPLAT_DBG_ASSERT(Builder->Key->HeaderKey != NULL);
        }

    } else {

        QuicTraceEvent(
            PacketFinalize,
            "[pack][%llu] Finalizing",
            Builder->Metadata->PacketId);
    }

    //
    // Track the sent packet.
    //
    CXPLAT_DBG_ASSERT(Builder->Metadata->FrameCount != 0);

    Builder->Metadata->SentTime = CxPlatTimeUs32();
    Builder->Metadata->PacketLength =
        Builder->HeaderLength + PayloadLength;
    Builder->Metadata->Flags.EcnEctSet = Builder->EcnEctSet;
    QuicTraceEvent(
        ConnPacketSent,
        "[conn][%p][TX][%llu] %hhu (%hu bytes)",
        Connection,
        Builder->Metadata->PacketNumber,
        QuicPacketTraceType(Builder->Metadata),
        Builder->Metadata->PacketLength);
    QuicLossDetectionOnPacketSent(
        &Connection->LossDetection,
        Builder->Path,
        Builder->Metadata);

    Builder->Metadata->FrameCount = 0;

    if (Builder->Metadata->Flags.IsAckEliciting) {
        Builder->PacketBatchRetransmittable = TRUE;

        //
        // Remove the bytes from the allowance.
        //
        if ((uint32_t)Builder->Metadata->PacketLength > Builder->SendAllowance) {
            Builder->SendAllowance = 0;
        } else {
            Builder->SendAllowance -= Builder->Metadata->PacketLength;
        }
    }

Exit:

    //
    // Send the packet out if necessary.
    //

    if (FinalQuicPacket) {
        if (Builder->Datagram != NULL) {
            if (Builder->Metadata->Flags.EcnEctSet) {
                ++Connection->Send.NumPacketsSentWithEct;
            }
            Builder->Datagram->Length = Builder->DatagramLength;
            Builder->Datagram = NULL;
            ++Builder->TotalCountDatagrams;
            Builder->TotalDatagramsLength += Builder->DatagramLength;
            Builder->DatagramLength = 0;
        }

        if (FlushBatchedDatagrams || CxPlatSendDataIsFull(Builder->SendData)) {
            if (Builder->BatchCount != 0) {
                QuicPacketBuilderFinalizeHeaderProtection(Builder);
            }
            CXPLAT_DBG_ASSERT(Builder->TotalCountDatagrams > 0);
#ifdef QUIC_BATCH_CRYPTO_HP
            QuicPacketBuilderCryptoBatch(Builder);
#endif
            if (Builder->SendData != NULL)
                QuicPacketBuilderSendBatch(Builder);
            CXPLAT_DBG_ASSERT(Builder->Metadata->FrameCount == 0);
            QuicTraceEvent(
                PacketBatchSent,
                "[pack][%llu] Batch sent",
                Builder->BatchId);
        }

        if ((Connection->Stats.QuicVersion != QUIC_VERSION_2 && Builder->PacketType == QUIC_RETRY_V1) ||
            (Connection->Stats.QuicVersion == QUIC_VERSION_2 && Builder->PacketType == QUIC_RETRY_V2)) {
            CXPLAT_DBG_ASSERT(Builder->Metadata->PacketNumber == 0);
            QuicConnCloseLocally(
                Connection,
                QUIC_CLOSE_SILENT,
                QUIC_ERROR_NO_ERROR,
                NULL);
        }

    } else if (FlushBatchedDatagrams) {
        if (Builder->Datagram != NULL) {
            CxPlatSendDataFreeBuffer(Builder->SendData, Builder->Datagram);
            Builder->Datagram = NULL;
            Builder->DatagramLength = 0;
        }
        if (Builder->SendData != NULL) {
            CxPlatSendDataFree(Builder->SendData);
            Builder->SendData = NULL;
        }
    }

    QuicPacketBuilderValidate(Builder, FALSE);

    CXPLAT_DBG_ASSERT(!FlushBatchedDatagrams || Builder->SendData == NULL);

    return CanKeepSending;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPacketBuilderSendBatch(
    _Inout_ QUIC_PACKET_BUILDER* Builder
    )
{
    QuicTraceLogConnVerbose(
        PacketBuilderSendBatch,
        Builder->Connection,
        "Sending batch. %hu datagrams",
        (uint16_t)Builder->TotalCountDatagrams);

    QuicBindingSend(
        Builder->Path->Binding,
        &Builder->Path->Route,
        Builder->SendData,
        Builder->TotalDatagramsLength,
        Builder->TotalCountDatagrams);

    Builder->PacketBatchSent = TRUE;
    Builder->SendData = NULL;
    Builder->TotalDatagramsLength = 0;
    Builder->Metadata->FrameCount = 0;
}

typedef enum _CpaBoolean
{
    CPA_FALSE = (0==1), /**< False value */
    CPA_TRUE = (1==1) /**< True value */
} CpaBoolean;

typedef int32_t Cpa32S;
typedef Cpa32S CpaStatus;
typedef void (*QuicCryptoBatchCB)(void* data);

//extern CpaStatus asynQatQuicEncrypt(uint8_t* pkey, uint8_t* iv, uint8_t *hdr, int hdr_len,
//    uint8_t *payload, int payload_len, uint8_t* hkey, CpaBoolean performOpNow, void* sendData);
extern CpaStatus asynQatQuicEncrypt(uint8_t* pkey, uint8_t* iv, uint8_t *hdr, int hdr_len, uint8_t *payload, int payload_len, 
    uint8_t* hkey, CpaBoolean performOpNow, void* sendData, unsigned int pn_len, unsigned int cid_len);

extern CpaStatus asynQatQuicComplete(QuicCryptoBatchCB cb);

CpaStatus _asynQatQuicEncrypt(void * cyInstHandle, void *sessionCtx, uint8_t* pkey, uint8_t* iv, uint8_t *hdr,
    int hdr_len, uint8_t *payload, int payload_len, uint8_t* hkey, CpaBoolean performOpNow,
    void* sendData, unsigned int pn_len, unsigned int cid_len);
CpaStatus _asynQatQuicComplete(void * cyInstHandleX, QuicCryptoBatchCB cb);


QUIC_STATUS
CxPlatSendDataSend(
    _In_ CXPLAT_SEND_DATA* SendData
    );

void QuicCryptoBatchCallback(void* data)
{
    CXPLAT_SEND_DATA* SendData = data;
    if (SendData != NULL)
    {
        QUIC_STATUS Status = CxPlatSendDataSend(SendData);
        //printf ("in callback, CxPlatSendDataSend %p .....%d \n", SendData, Status);
        if (Status == QUIC_STATUS_SUCCESS)
        {
            //CxPlatListEntryRemove(&p_send_data->TxEntry);
            CxPlatSendDataFree(SendData);
            //printf("  Free SendData %p\n",SendData);
        }
    }
}

#if 1
static void hexdump(const char *title, const uint8_t *p, size_t l)
{
    // #define DEBUG_DUMP
    title = title;
    p = p;
    l = l;

    // #ifdef DEBUG_DUMP
    printf("%s (%zu bytes):\n", title, l);

    while (l != 0) {
        int i;
        printf("   ");
        for (i = 0; i < 16; ++i) {
            printf(" %02x", *p++);
            if (--l == 0)
                break;
        }
        printf("\n");
    }
    // #endif
}
#endif

#include <intel-ipsec-mb.h>
#define KEY_SIZE 16
#define IV_SIZE 12
#define AUTH_TAG_LEN 16
#define DATA_SIZE 1024

int ipsecmb_test(IMB_MGR *p_mgr)
{
    uint8_t key[KEY_SIZE] = {0x66};
    uint8_t iv[IV_SIZE] = {0x33};
    uint8_t src_data[DATA_SIZE] = {0x11};
    uint8_t dst_data[DATA_SIZE + 16] = {0x22};
    uint8_t aad[16] = {0x44};
    uint8_t *tag = &dst_data[DATA_SIZE];

    struct gcm_key_data gdata_key;
    memset(&gdata_key, 0, sizeof(struct gcm_key_data));
    IMB_AES128_GCM_PRE(p_mgr, &key, &gdata_key);

    void *src_ptr_array = &src_data;
    void *dst_ptr_array = &dst_data;
    uint64_t len_array = DATA_SIZE;
    void *iv_ptr_array = &iv;
    void *aad_ptr_array = &aad;
    uint64_t aad_len = 16;
    void *tag_ptr_array = &tag;
    uint64_t tag_len = 16;
    uint64_t num_packets = 1;

    hexdump("src", src_data, DATA_SIZE);
    printf("imb_get_errno 1 returns %d\n", imb_get_errno(p_mgr));
    imb_quic_aes_gcm(p_mgr, &gdata_key, 16, IMB_DIR_ENCRYPT, (void **)&dst_ptr_array, (const void *const *)&src_ptr_array,
                     &len_array, (const void *const *)&iv_ptr_array, (const void *const *)&aad_ptr_array, aad_len, (void **)&tag_ptr_array, tag_len, num_packets);
    hexdump("dst", dst_data, DATA_SIZE);
    printf("imb_get_errno 2 returns %d\n", imb_get_errno(p_mgr));

    return 0;
}

int32_t _asynQatQuicSetKey(void *sessionCtx, uint8_t *pkey);

QUIC_STATUS CxPlatSocketSet(
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    );

_IRQL_requires_max_(PASSIVE_LEVEL) void QuicPacketBuilderCryptoBatch(
    _Inout_ QUIC_PACKET_BUILDER *Builder)
{
    Builder = Builder;
    if (Builder->BCQuicAmount == 0)
        return;

#define BATCH_WITH_IPSEMB 1
#ifdef BATCH_WITH_IPSEMB
    if (Builder->Connection->keySet == 0)
    {
        memset(Builder->Connection->gdata_key, 0, sizeof(struct gcm_key_data));
        hexdump("gcm key string", (const uint8_t *)Builder->Key->pk, 16);
        IMB_AES128_GCM_PRE((IMB_MGR *)Builder->Connection->p_mgr, &Builder->Key->pk, Builder->Connection->gdata_key);

        memset(Builder->Connection->gdata_key_ext, 0, sizeof(struct gcm_key_data));
        hexdump("hp key string", (const uint8_t *)Builder->Key->hk, 16);
        IMB_AES128_GCM_PRE((IMB_MGR *)Builder->Connection->p_mgr_ext, &Builder->Key->hk, Builder->Connection->gdata_key_ext);

        Builder->Connection->keySet = 1;
    }

    void *src_ptr_array[64] = {0};
    void *dst_ptr_array[64] = {0};
    uint64_t len_array[64] = {0};
    void *iv_ptr_array[64] = {0};
    void *aad_ptr_array[64] = {0};
    void *tag_ptr_array[64] = {0};
    uint64_t aad_len = Builder->HeaderLength;
    uint64_t tag_len = 16;
    uint64_t num_packets = Builder->BCQuicAmount;
    uint8_t HpMask[64 * 8] = {0};
    void *hp_dst_arrary[64] ={0};

    for (int i = 0; i < Builder->BCQuicAmount; i++)
    {
        src_ptr_array[i] = Builder->BCQuicPayload[i];
        dst_ptr_array[i] = Builder->BCQuicPayload[i];
        len_array[i] = Builder->BCQuicPayloadLength[i] - 16;
        iv_ptr_array[i] = (void *)((uint64_t)&Builder->BCQuicIV + CXPLAT_MAX_IV_LENGTH * i);
        aad_ptr_array[i] = Builder->BCQuicHdr[i];
        tag_ptr_array[i] = (void *)((uint64_t)Builder->BCQuicPayload[i] + Builder->BCQuicPayloadLength[i] - 16);
        hp_dst_arrary[i] = (void *)((uint64_t)&HpMask + 8 * i);
    }
    //printf ("aes-gcm batch size %d\n", Builder->BCQuicAmount);

#ifndef QUIC_BYPASS_CRYPTO
    imb_quic_aes_gcm((IMB_MGR *)Builder->Connection->p_mgr, Builder->Connection->gdata_key, IMB_KEY_128_BYTES, IMB_DIR_ENCRYPT,
                     (void **)&dst_ptr_array, (const void *const *)&src_ptr_array,
                     (const uint64_t *)&len_array, (const void *const *)&iv_ptr_array, (const void *const *)&aad_ptr_array,
                     aad_len, (void **)&tag_ptr_array, tag_len, num_packets);
#else
        src_ptr_array[0] = src_ptr_array[0];
        dst_ptr_array[0] = dst_ptr_array[0];
        len_array[0] = len_array[0];
        iv_ptr_array[0] = iv_ptr_array[0];
        aad_ptr_array[0] = aad_ptr_array[0];
        tag_ptr_array[0] = tag_ptr_array[0];
        hp_dst_arrary[0] = hp_dst_arrary[0];
        num_packets = num_packets;
        tag_len = tag_len;
        aad_len = aad_len;
#endif
    /* 9.86Gbps/2T1C, ipsecmb encryption + bypass hp
        Children      Self  Shared Object           
    +   63.87%     0.00%  [unknown]               
    +   48.03%    47.15%  libmsquic.so.2.2.0      
    +   27.01%    12.32%  libc-2.28.so            
    -   24.09%    24.09%  [kernel.kallsyms]       
    - 23.03% 0                                 
        + 11.61% read                           
        + 6.34% 0x7f800000001c                  
        + 4.60% 0x1c                            
    + 1.04% recvmmsg                           
    -   14.70%     3.76%  libpthread-2.28.so      
    + 10.95% __libc_sendmsg                    
    + 0.86% 0xec83485355544155                 
    +   10.98%    10.98%  libIPSec_MB.so.1.4.0-dev
    +    1.71%     1.68%  [vdso]                  
        0.03%     0.03%  quicinteropserver       
        0.00%     0.00%  perf                    
    */

#ifndef QUIC_BYPASS_HP
    imb_quic_hp_aes_ecb((IMB_MGR *)Builder->Connection->p_mgr_ext, Builder->Connection->gdata_key_ext,
        (void **)&hp_dst_arrary, (const void * const*)&src_ptr_array, num_packets, IMB_KEY_128_BYTES);
    //printf ("imb_quic_hp_aes_ecb output  0x%02x    0x%08x \n", HpMask[0], *(unsigned int *)(&HpMask[1]));

    /* 9.9Gbps, ipsecmb encryption + ipsecmb batch hp 
    Children      Self  Shared Object
    +   63.76%     0.00%  [unknown]
    +   47.44%    46.39%  libmsquic.so.2.2.0
    +   26.56%    13.04%  libc-2.28.so
    +   23.38%    23.38%  [kernel.kallsyms]
    +   15.20%     3.81%  libpthread-2.28.so
    +   11.61%    11.60%  libIPSec_MB.so.1.4.0-dev
    +    1.76%     1.76%  [vdso]
        0.01%     0.01%  quicinteropserver
        0.00%     0.00%  perf
    */
#endif

    for (int i = 0; i < Builder->BCQuicAmount; i++)
    {
        uint8_t *Header = Builder->BCQuicHdr[i];


        #ifdef QUIC_BYPASS_HP
            uint8_t *PnStart = Builder->BCQuicPayload[i] - Builder->PacketNumberLength;
            CxPlatCopyMemory(hp_dst_arrary[i], PnStart + 4, CXPLAT_HP_SAMPLE_LENGTH);
        #endif

        Header[0] ^= ((*(uint8_t *)hp_dst_arrary[i]) & 0x1f); // Bottom 5 bits for SH

        if (Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE)
        {
            Header += 1 + Builder->Path->DestCid->CID.Length;
        }
        else
        {
            assert(0);
            Header = Builder->BCQuicPayload[i] - Builder->PacketNumberLength;
        }

        for (uint8_t j = 0; j < Builder->PacketNumberLength; ++j)
        {
            Header[j] ^= *((uint8_t *)hp_dst_arrary[i] + 1 + j);
        }
    }

    Builder->BCQuicAmount = 0;
    return;

#endif // End of BATCH_WITH_IPSECMB

    for (int i = 0; i < Builder->BCQuicAmount; i++)
    {
        //printf ("aes-gcm batch size %d\n", Builder->BCQuicAmount);
#ifndef QUIC_BYPASS_CRYPTO

#ifdef QUIC_ASYNC_CRYPTO
        // provision key into QAT till 1st Tx, doesn't support key refresh/update yet
        if (Builder->Connection->keySet == 0)
        {
            //printf ("Prepare key setup, conn = %p, sessionctx = %p, key = %p\n",
            //    Builder->Connection, Builder->Connection->sessionCtx, Builder->Key->pk);
            _asynQatQuicSetKey(Builder->Connection->sessionCtx, (uint8_t *)&Builder->Key->pk);
            Builder->Connection->keySet = 1;
        }

        // 9.07Gbps/2T1C, qat encryption + bypass hp
        /*
        0.00%  [unknown]
        +   42.84%    41.87%  libmsquic.so.2.2.0
        -   32.48%    19.38%  libc-2.28.so
        + 10.41% read
            4.12% __memmove_avx_unaligned_erms
        + 4.07% 0x58300000000
        + 1.29% clock_gettime@GLIBC_2.2.5
        + 0.90% recvmmsg
            0.53% _int_malloc
        -   22.61%    22.61%  [kernel.kallsyms]
        - 21.37% 0
            - 10.57% 0x7f690000001c
                + 10.56% __libc_sendmsg
            + 10.40% read
        + 0.88% recvmmsg
        +   14.11%     3.51%  libpthread-2.28.so
        +    5.11%     5.08%  libqat_s.so
        +    4.92%     4.90%  libquic_crypto_s.so
        +    1.44%     1.44%  [vdso]
            1.14%     1.14%  libusdm_drv_s.so
            0.07%     0.07%  quicinteropserver
            0.00%     0.00%  perf
        */
        _asynQatQuicEncrypt(Builder->Connection->Worker->cyInstHandleX, Builder->Connection->sessionCtx,
                            Builder->Key->pk, Builder->BCQuicIV + CXPLAT_MAX_IV_LENGTH * i,
                            Builder->BCQuicHdr[i], Builder->HeaderLength,
            Builder->BCQuicPayload[i], Builder->BCQuicPayloadLength[i] ,
            //Builder->Key->hk,
            (uint8_t*)Builder->Key->HeaderKey, // key format used by OpenSSL
                            (i == Builder->BCQuicAmount - 1) ? CPA_TRUE : CPA_FALSE,
                            Builder->SendData,
                            Builder->PacketNumberLength,
                            Builder->Path->DestCid->CID.Length);

        // async mode
        if (i == Builder->BCQuicAmount - 1)
        {
            CxPlatSocketSet(&Builder->Path->Route, Builder->SendData);
            Builder->SendData = NULL;
        }

        //hexdump("Encrypted text data ", Builder->BCQuicPayload[i], Builder->BCQuicPayloadLength[i]);
#else  // QUIC_ASYNC_CRYPTO not defined

        uint8_t* PnStart = Builder->BCQuicPayload[i] - Builder->PacketNumberLength;

    //#define IPSECMB_CRYPTO 1
    #if PICOTLS_CRYPTO
        // picotls crypto, functionality not ready yet
        static ptls_aead_context_t *aead = 0;
        if (aead == 0)
            aead = ptls_aead_new_direct(&ptls_fusion_aes128gcm, 1, Builder->Key->pk,
                                        Builder->BCQuicIV + CXPLAT_MAX_IV_LENGTH * i);

        uint8_t encrypted[2000];
        ptls_aead_encrypt(aead, &encrypted, Builder->BCQuicPayload[i], Builder->BCQuicPayloadLength[i],
                          Builder->BCQuicSN[i], Builder->BCQuicHdr[i], Builder->HeaderLength);
    #elif IPSECMB_CRYPTO
        // ipsecmb_test(Builder->Connection->p_mgr);

        if (Builder->Connection->keySet == 0)
        {
            memset(Builder->Connection->gdata_key, 0, sizeof(struct gcm_key_data));
            hexdump("gcm key string", (const uint8_t *)Builder->Key->pk, 16);
            IMB_AES128_GCM_PRE((IMB_MGR *)Builder->Connection->p_mgr, &Builder->Key->pk, Builder->Connection->gdata_key);

            memset(Builder->Connection->gdata_key_ext, 0, sizeof(struct gcm_key_data));
            hexdump("hp key string", (const uint8_t *)Builder->Key->hk, 16);
            IMB_AES128_GCM_PRE((IMB_MGR *)Builder->Connection->p_mgr_ext, &Builder->Key->hk, Builder->Connection->gdata_key_ext); 

            Builder->Connection->keySet = 1;
        }

        {
            void *src_ptr_array = Builder->BCQuicPayload[i];
            void *dst_ptr_array = Builder->BCQuicPayload[i];
            uint64_t len_array = Builder->BCQuicPayloadLength[i] - 16;
            void *iv_ptr_array = (void *)((uint64_t)&Builder->BCQuicIV + CXPLAT_MAX_IV_LENGTH * i);
            void *aad_ptr_array = Builder->BCQuicHdr[i];
            uint64_t aad_len = Builder->HeaderLength;
            void *tag_ptr_array = (void *)((uint64_t)Builder->BCQuicPayload[i] + Builder->BCQuicPayloadLength[i] - 16);
            //printf ("Builder->BCQuicIV = %p, iv_ptr_array =%p, src_ptr_array = %p, Builder->BCQuicPayload[i] = %p, 
            //len_array = %ld, aad_len = %ld, tag_ptr_array[0] = %p\n",
            // &Builder->BCQuicIV, iv_ptr_array, src_ptr_array, 
            // Builder->BCQuicPayload[i], len_array, aad_len, tag_ptr_array);
            uint64_t tag_len = 16;
            uint64_t num_packets = 1;

            #if 0
             uint8_t tmp_buf[2000];
             tmp_buf[0] = tmp_buf[0];
             memcpy (tmp_buf, Builder->BCQuicPayload[i], Builder->BCQuicPayloadLength[i]);
            #endif

            imb_quic_aes_gcm((IMB_MGR *)Builder->Connection->p_mgr, Builder->Connection->gdata_key, IMB_KEY_128_BYTES, IMB_DIR_ENCRYPT,
                             (void **)&dst_ptr_array, (const void *const *)&src_ptr_array,
                             &len_array, (const void *const *)&iv_ptr_array, (const void *const *)&aad_ptr_array,
                             aad_len, (void **)&tag_ptr_array, tag_len, num_packets);
            //printf("imb_get_errno returns %d\n", imb_get_errno((IMB_MGR *)Builder->Connection->p_mgr));
        }
        /* 9.89Gbps, 2T1C, aes-128-gcm, bypass-hp 
                Children      Self  Shared Object
        +   63.11%     0.00%  [unknown]
        +   46.44%    45.35%  libmsquic.so.2.2.0
        +   27.03%    11.92%  libc-2.28.so
        +   25.15%    25.15%  [kernel.kallsyms]
        +   15.19%     4.23%  libpthread-2.28.so
        +   11.56%    11.53%  libIPSec_MB.so.1.4.0-dev
        +    1.80%     1.80%  [vdso]
            0.02%     0.02%  quicinteropserver
            0.00%     0.00%  perf
        */

    #else

        //hexdump("src - default", Builder->BCQuicPayload[i], Builder->BCQuicPayloadLength[i]);
        CxPlatEncrypt(Builder->Key->PacketKey, Builder->BCQuicIV + CXPLAT_MAX_IV_LENGTH * i,
                      Builder->HeaderLength, Builder->BCQuicHdr[i], Builder->BCQuicPayloadLength[i],
                      Builder->BCQuicPayload[i]);

        #if 0
        if (memcmp(tmp_buf, Builder->BCQuicPayload[i], Builder->BCQuicPayloadLength[i]) != 0)
        {
            printf ("Crypto error happens (idex %d of total %d)\n", i, Builder->BCQuicAmount);
            //hexdump("dst - ipsecmb", Builder->BCQuicPayload[i], Builder->BCQuicPayloadLength[i]);
            //hexdump("dst - default (expected)", tmp_buf, Builder->BCQuicPayloadLength[i]);
        }
        else
        {
            printf ("Crypto good (idex %d of total %d)\n", i, Builder->BCQuicAmount);
        }
        #endif
    #endif

        uint8_t HpMask[128];
        uint8_t *Header = Builder->BCQuicHdr[i];
        //uint8_t *PnStart = Builder->BCQuicPayload[i] - Builder->PacketNumberLength;

    #ifndef QUIC_BYPASS_HP
        #ifdef IPSECMB_CRYPTO
        {
            void *src_ptr_array = PnStart + 4;
            void *dst_ptr_array = &HpMask;
            IMB_KEY_SIZE_BYTES key_size = IMB_KEY_128_BYTES;
            uint64_t num_packets = 1;

            imb_quic_hp_aes_ecb((IMB_MGR *)Builder->Connection->p_mgr_ext, Builder->Connection->gdata_key_ext,
            //imb_quic_hp_aes_ecb((IMB_MGR *)Builder->Connection->p_mgr_ext, Builder->Connection->gdata_key,
                &dst_ptr_array, (const void * const*)&src_ptr_array, num_packets, key_size);
            //printf ("imb_quic_hp_aes_ecb output  0x%02x    0x%08x \n", HpMask[0], *(unsigned int *)(&HpMask[1]));
        }
        #else
        CxPlatHpComputeMask(Builder->Key->HeaderKey, 1, PnStart + 4, HpMask);
        //printf ("CxPlatHpComputeMask output 0x%02x    0x%08x\n", HpMask[0], *(unsigned int *)(&HpMask[1]));
        #endif
    #else
        CxPlatCopyMemory(HpMask, PnStart + 4, CXPLAT_HP_SAMPLE_LENGTH);
    #endif

        Header[0] ^= (HpMask[0] & 0x1f); // Bottom 5 bits for SH

        if (Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE)
        {
            Header += 1 + Builder->Path->DestCid->CID.Length;
        } else
        {
            assert (0);
            Header = Builder->BCQuicPayload[i] - Builder->PacketNumberLength;
        }

        for (uint8_t j = 0; j < Builder->PacketNumberLength; ++j) {
            Header[j] ^= HpMask[1 + j];
        }
#endif // QUIC_ASYNC_CRYPTO

#else // QUIC_BYPASS_CRYPTO
        uint8_t *PnStart = Builder->BCQuicPayload[i] - Builder->PacketNumberLength;

        // code use to evaluate crypto overhead
        uint8_t tmp_buf[2000];
        tmp_buf[0] = tmp_buf[0];

//#define DUMMY_IPSECMB_CRYPTO 1
#if DUMMY_IPSECMB_CRYPTO
        if (Builder->Connection->keySet == 0)
        {
            memset(Builder->Connection->gdata_key, 0, sizeof(struct gcm_key_data));
            hexdump("gcm key string", (const uint8_t *)Builder->Key->pk, 32);
            hexdump("gcm_key_data ......(before setup)", Builder->Connection->gdata_key, sizeof(struct gcm_key_data));
            IMB_AES128_GCM_PRE((IMB_MGR *)Builder->Connection->p_mgr, &Builder->Key->pk, Builder->Connection->gdata_key);
            hexdump("gcm_key_data ......(after setup)", Builder->Connection->gdata_key, sizeof(struct gcm_key_data));
            Builder->Connection->keySet = 1;
        }

        {
            void *src_ptr_array = Builder->BCQuicPayload[i];
            void *dst_ptr_array = Builder->BCQuicPayload[i];
            uint64_t len_array = Builder->BCQuicPayloadLength[i] - 16;
            void *iv_ptr_array = &Builder->BCQuicIV + CXPLAT_MAX_IV_LENGTH * i;
            void *aad_ptr_array = Builder->BCQuicHdr[i];
            uint64_t aad_len = Builder->HeaderLength;
            void *tag_ptr_array = (void *)((uint64_t)Builder->BCQuicPayload[i] + Builder->BCQuicPayloadLength[i] - 16);
            printf("Builder->BCQuicIV = %p, iv_ptr_array =%p, src_ptr_array = %p, Builder->BCQuicPayload[i] = %p, len_array = %ld, aad_len = %ld, tag_ptr_array[0] = %p\n",
                   &Builder->BCQuicIV, iv_ptr_array, src_ptr_array, Builder->BCQuicPayload[i], len_array, aad_len, tag_ptr_array);
            uint64_t tag_len = 16;
            uint64_t num_packets = 1;

            uint8_t tmp_buf[2000];
            tmp_buf[0] = tmp_buf[0];
            memcpy(tmp_buf, Builder->BCQuicPayload[i], Builder->BCQuicPayloadLength[i]);

            hexdump("src - ipsecmb", Builder->BCQuicPayload[i], Builder->BCQuicPayloadLength[i]);
            imb_quic_aes_gcm((IMB_MGR *)Builder->Connection->p_mgr, Builder->Connection->gdata_key, IMB_KEY_128_BYTES, IMB_DIR_ENCRYPT,
                             (void **)&dst_ptr_array, (const void *const *)&src_ptr_array,
                             &len_array, (const void *const *)&iv_ptr_array, (const void *const *)&aad_ptr_array,
                             aad_len, (void **)&tag_ptr_array, tag_len, num_packets);
            hexdump("dst - ipsecmb", Builder->BCQuicPayload[i], Builder->BCQuicPayloadLength[i]);
        }
#endif

#if DUMMY_PICOTLS_CRYPTO
        // picotls crypto
        // msquic 39%, fusion 24%, kernel 23%(read 12%, sendmsg 8%)
        // 8.97Gbps/2T1C - 7.36Gbps/1T1C,
        // picotls crypto(cycle cost included but result not verified), bypass HP
        /*
          Children      Self  Shared Object
        +   68.53%     0.00%  [unknown]
        +   39.54%    38.67%  libmsquic.so.2.2.0
        +   24.83%     9.84%  libc-2.28.so
            23.79%    23.76%  libpicotls-fusion.so
        +   22.93%    22.93%  [kernel.kallsyms]
        +   12.23%     3.18%  libpthread-2.28.so
        +    1.61%     1.60%  [vdso]
            0.01%     0.01%  quicinteropserver
            0.00%     0.00%  perf
        */
        static ptls_aead_context_t *aead = 0;
        if (aead == 0)
            aead = ptls_aead_new_direct(&ptls_fusion_aes128gcm, 1, Builder->Key->pk,
                                        Builder->BCQuicIV + CXPLAT_MAX_IV_LENGTH * i);

        ptls_aead_encrypt(aead, &tmp_buf, Builder->BCQuicPayload[i], Builder->BCQuicPayloadLength[i],
                          Builder->BCQuicSN[i], Builder->BCQuicHdr[i], Builder->HeaderLength);
#endif

#if DUMMY_QUICTLS_CRYPTO
        // quictls/openssl crypto
        // 7.23Gbps/2T1C
        // OpenSSL crypto(cycle cost included, additional memcpy for payload save/restore), bypass HP
        /*
                Children      Self  Shared Object
        +   67.18%    66.33%  libmsquic.so.2.2.0
        +   38.92%     0.00%  [unknown]
        +   22.83%    12.44%  libc-2.28.so
        +   17.23%    17.23%  [kernel.kallsyms]
        +   10.47%     2.67%  libpthread-2.28.so
        +    1.31%     1.31%  [vdso]
            0.02%     0.02%  quicinteropserver
            0.00%     0.00%  perf
        */
        memcpy (tmp_buf, Builder->BCQuicPayload[i], Builder->BCQuicPayloadLength[i]);
                CxPlatEncrypt(Builder->Key->PacketKey,Builder->BCQuicIV + CXPLAT_MAX_IV_LENGTH * i,
                      Builder->HeaderLength, Builder->BCQuicHdr[i], Builder->BCQuicPayloadLength[i],
                      Builder->BCQuicPayload[i]);
        memcpy(Builder->BCQuicPayload[i], tmp_buf, Builder->BCQuicPayloadLength[i]);
#endif

        // Or 11.4Gbps/2T1C, bypass crypto/hp
        // perf: read 12%, 10% sendmsg
        /*
                Children      Self  Shared Object
        +   59.00%     0.00%  [unknown]
        +   52.60%    51.58%  libmsquic.so.2.2.0
        +   30.81%    15.48%  libc-2.28.so
        +   26.56%    26.56%  [kernel.kallsyms]
        +   17.42%     4.42%  libpthread-2.28.so
        +    1.94%     1.94%  [vdso]
            0.02%     0.02%  quicinteropserver
            0.00%     0.00%  perf
        */

        uint8_t HpMask[128];
        uint8_t *Header = Builder->BCQuicHdr[i];

#ifndef QUIC_BYPASS_HP
        CxPlatHpComputeMask(Builder->Key->HeaderKey, 1, PnStart + 4, HpMask);
#else
        CxPlatCopyMemory(HpMask, PnStart + 4, CXPLAT_HP_SAMPLE_LENGTH);
#endif

        Header[0] ^= (HpMask[0] & 0x1f); // Bottom 5 bits for SH

        if (Builder->PacketType == SEND_PACKET_SHORT_HEADER_TYPE)
        {
            Header += 1 + Builder->Path->DestCid->CID.Length;
        } else
        {
            assert (0);
            Header = Builder->BCQuicPayload[i] - Builder->PacketNumberLength;
        }

        for (uint8_t j = 0; j < Builder->PacketNumberLength; ++j) {
            Header[j] ^= HpMask[1 + j];
        }
#endif
    }

#ifdef QUIC_ASYNC_CRYPTO
    _asynQatQuicComplete(Builder->Connection->Worker->cyInstHandleX, QuicCryptoBatchCallback);
#endif
    Builder->BCQuicAmount = 0;

}

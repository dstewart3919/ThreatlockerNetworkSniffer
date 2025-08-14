/*++
 * ThreatLockerNetworkSniffer - Minimal NDIS LWF with IPv4 parse, whitelist check,
 * and decision ring for user-mode logging.
--*/
#include "precomp.h"

#define __FILENUMBER    'TLPN'

NDIS_HANDLE         FilterDriverHandle = NULL;
NDIS_HANDLE         FilterDriverObject = NULL;
NDIS_HANDLE         NdisFilterDeviceHandle = NULL;
PDEVICE_OBJECT      NdisDeviceObject = NULL;

// ---------------- Whitelist & ring (kernel store) ----------------
typedef struct _TL_WL_TABLE {
    TL_WL_NODE* Buckets[TL_HASH_BUCKETS];
    FILTER_LOCK Lock;
    NPAGED_LOOKASIDE_LIST NodePool;
} TL_WL_TABLE;

static TL_WL_TABLE gWl;
static TL_DECISION_RING gRing;

static __forceinline ULONG TlHash(ULONG ip, USHORT port, UCHAR proto) {
    ULONG x = ip ^ ((ULONG)port << 16) ^ proto;
    x ^= x >> 16; x *= 0x7feb352d; x ^= x >> 15; x *= 0x846ca68b; x ^= x >> 16;
    return x & (TL_HASH_BUCKETS - 1);
}

NTSTATUS TlWhitelistInit(VOID)
{
    RtlZeroMemory(&gWl, sizeof(gWl));
    FILTER_INIT_LOCK(&gWl.Lock);
    ExInitializeNPagedLookasideList(&gWl.NodePool, NULL, NULL, 0, sizeof(TL_WL_NODE), FILTER_ALLOC_TAG, 0);
    return STATUS_SUCCESS;
}
static VOID TlWhitelistClearLocked(VOID)
{
    for (ULONG i=0;i<TL_HASH_BUCKETS;i++){
        TL_WL_NODE* n = gWl.Buckets[i];
        while (n){ TL_WL_NODE* nx = n->Next; ExFreeToNPagedLookasideList(&gWl.NodePool, n); n = nx; }
        gWl.Buckets[i] = NULL;
    }
}
VOID TlWhitelistFree(VOID)
{
    NdisAcquireSpinLock(&gWl.Lock);
    TlWhitelistClearLocked();
    FILTER_RELEASE_LOCK(&gWl.Lock, FALSE);
    ExDeleteNPagedLookasideList(&gWl.NodePool);
    FILTER_FREE_LOCK(&gWl.Lock);
}
NTSTATUS TlWhitelistReplace(const TL_SET_WHITELIST* wl, ULONG len)
{
    if (len < sizeof(TL_SET_WHITELIST)) return STATUS_BUFFER_TOO_SMALL;
    ULONG count = wl->Count;
    SIZE_T need = sizeof(TL_SET_WHITELIST) + (SIZE_T)count * sizeof(TL_ENTRY_V4);
    if (len < need) return STATUS_INVALID_PARAMETER;
    const TL_ENTRY_V4* items = (const TL_ENTRY_V4*)(wl + 1);

    NdisAcquireSpinLock(&gWl.Lock);
    TlWhitelistClearLocked();
    for (ULONG i=0;i<count;i++){
        const TL_ENTRY_V4* e = &items[i];
        TL_WL_NODE* n = (TL_WL_NODE*)ExAllocateFromNPagedLookasideList(&gWl.NodePool);
        if (!n) { TlWhitelistClearLocked(); FILTER_RELEASE_LOCK(&gWl.Lock, FALSE); return STATUS_INSUFFICIENT_RESOURCES; }
        n->DstIpV4 = e->DstIpV4; n->DstPort = e->DstPort; n->Proto = e->Proto;
        ULONG b = TlHash(n->DstIpV4, n->DstPort, n->Proto);
        n->Next = gWl.Buckets[b];
        gWl.Buckets[b] = n;
    }
    FILTER_RELEASE_LOCK(&gWl.Lock, FALSE);
    return STATUS_SUCCESS;
}
BOOLEAN TlWhitelistMatchV4(ULONG ipNbo, USHORT portNbo, UCHAR proto)
{
    ULONG b = TlHash(ipNbo, portNbo, proto);
    NdisAcquireSpinLock(&gWl.Lock);
    TL_WL_NODE* n = gWl.Buckets[b];
    for (; n; n = n->Next){
        if (n->DstIpV4 == ipNbo && n->DstPort == portNbo && (n->Proto==0 || n->Proto==proto)){
            FILTER_RELEASE_LOCK(&gWl.Lock, TRUE);
            return TRUE;
        }
    }
    FILTER_RELEASE_LOCK(&gWl.Lock, TRUE);
    return FALSE;
}

// --------- Decision ring ---------
NTSTATUS TlRingInit(VOID)
{
    gRing.Buf = (TL_DECISION_V4*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        TL_RING_CAPACITY * sizeof(TL_DECISION_V4),
        FILTER_ALLOC_TAG);
    if (!gRing.Buf) return STATUS_INSUFFICIENT_RESOURCES;
    gRing.Head = gRing.Tail = 0;
    return STATUS_SUCCESS;
}
VOID TlRingFree(VOID)
{
    if (gRing.Buf) { ExFreePoolWithTag(gRing.Buf, FILTER_ALLOC_TAG); gRing.Buf = NULL; }
}
VOID TlRingPushDecision(const TL_DECISION_V4* d)
{
    ULONG h = gRing.Head;
    ULONG t = gRing.Tail;
    ULONG next = (h + 1) % TL_RING_CAPACITY;
    if (next == t) {
        gRing.Tail = (t + 1) % TL_RING_CAPACITY;
    }
    gRing.Buf[h] = *d;
    gRing.Head = next;
}
ULONG TlRingPopBatch(TL_DECISION_V4* out, ULONG max)
{
    ULONG n = 0;
    while (n < max) {
        ULONG t = gRing.Tail, h = gRing.Head;
        if (t == h) break;
        out[n++] = gRing.Buf[t];
        gRing.Tail = (t + 1) % TL_RING_CAPACITY;
    }
    return n;
}

// ---------------- NDIS filter boilerplate ----------------

static VOID FilterUnload(_In_ PDRIVER_OBJECT DriverObject);
static NDIS_STATUS FilterRegisterOptions(NDIS_HANDLE NdisFilterDriverHandle, NDIS_HANDLE FilterDriverContext);
static NDIS_STATUS FilterAttach(NDIS_HANDLE NdisFilterHandle, NDIS_HANDLE FilterDriverContext, PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters);
static VOID FilterDetach(NDIS_HANDLE FilterModuleContext);
static NDIS_STATUS FilterRestart(NDIS_HANDLE FilterModuleContext, PNDIS_FILTER_RESTART_PARAMETERS RestartParameters);
static NDIS_STATUS FilterPause(NDIS_HANDLE FilterModuleContext, PNDIS_FILTER_PAUSE_PARAMETERS PauseParameters);
static VOID FilterReceiveNetBufferLists(NDIS_HANDLE FilterModuleContext, PNET_BUFFER_LIST NetBufferLists, NDIS_PORT_NUMBER PortNumber, ULONG NumberOfNetBufferLists, ULONG ReceiveFlags);
static VOID FilterReturnNetBufferLists(NDIS_HANDLE FilterModuleContext, PNET_BUFFER_LIST NetBufferLists, ULONG ReturnFlags);
static VOID FilterSendNetBufferLists(NDIS_HANDLE FilterModuleContext, PNET_BUFFER_LIST NetBufferLists, NDIS_PORT_NUMBER PortNumber, ULONG SendFlags);
static VOID FilterSendNetBufferListsComplete(NDIS_HANDLE FilterModuleContext, PNET_BUFFER_LIST NetBufferLists, ULONG SendCompleteFlags);

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
#pragma NDIS_INIT_FUNCTION(DriverEntry)

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DEBUGP(DL_TRACE, "===> DriverEntry\n");

    NDIS_FILTER_DRIVER_CHARACTERISTICS fchars = {0};
    fchars.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
    fchars.Header.Size = sizeof(fchars);
    fchars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
    fchars.MajorNdisVersion = FILTER_MAJOR_NDIS_VERSION;
    fchars.MinorNdisVersion = FILTER_MINOR_NDIS_VERSION;
    fchars.MajorDriverVersion = 1;
    fchars.MinorDriverVersion = 0;
    fchars.Flags = 0;
    UNICODE_STRING friendly, unique, service;
    RtlInitUnicodeString(&friendly, FILTER_FRIENDLY_NAME);
    RtlInitUnicodeString(&unique, FILTER_UNIQUE_NAME);
    RtlInitUnicodeString(&service, FILTER_SERVICE_NAME);

    fchars.FriendlyName = friendly;
    fchars.UniqueName = unique;
    fchars.ServiceName = service;

    fchars.SetOptionsHandler = FilterRegisterOptions;
    fchars.AttachHandler = FilterAttach;
    fchars.DetachHandler = FilterDetach;
    fchars.RestartHandler = FilterRestart;
    fchars.PauseHandler = FilterPause;

    // Data path handlers
    fchars.SendNetBufferListsHandler = FilterSendNetBufferLists;
    fchars.ReturnNetBufferListsHandler = FilterReturnNetBufferLists;
    fchars.SendNetBufferListsCompleteHandler = FilterSendNetBufferListsComplete;
    fchars.ReceiveNetBufferListsHandler = FilterReceiveNetBufferLists;

    DriverObject->DriverUnload = FilterUnload;

    NDIS_STATUS status = NdisFRegisterFilterDriver(DriverObject, (NDIS_HANDLE)DriverObject,
                                                   &fchars, &FilterDriverHandle);
    if (status != NDIS_STATUS_SUCCESS) {
        DEBUGP(DL_ERROR, "NdisFRegisterFilterDriver failed %x\n", status);
        return status;
    }

    status = FilterRegisterDevice();
    if (status != NDIS_STATUS_SUCCESS) {
        NdisFDeregisterFilterDriver(FilterDriverHandle);
        DEBUGP(DL_ERROR, "FilterRegisterDevice failed %x\n", status);
        return status;
    }

    if (!NT_SUCCESS(status = TlWhitelistInit())) return status;
    if (!NT_SUCCESS(status = TlRingInit())) return status;

    DEBUGP(DL_TRACE, "<=== DriverEntry OK\n");
    return STATUS_SUCCESS;
}

static VOID FilterUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DEBUGP(DL_TRACE, "===> FilterUnload\n");
    TlRingFree();
    TlWhitelistFree();
    FilterDeregisterDevice();
    if (FilterDriverHandle) {
        NdisFDeregisterFilterDriver(FilterDriverHandle);
        FilterDriverHandle = NULL;
    }
    DEBUGP(DL_TRACE, "<=== FilterUnload\n");
}

static NDIS_STATUS FilterRegisterOptions(NDIS_HANDLE a, NDIS_HANDLE b)
{
    UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(b); return NDIS_STATUS_SUCCESS;
}

typedef struct _MS_FILTER {
    NDIS_HANDLE FilterHandle;
    ULONG       State;
    FILTER_LOCK Lock;
    ULONG       OutstandingSends;
    BOOLEAN     TrackSends;
    BOOLEAN     TrackReceives;
} MS_FILTER, *PMS_FILTER;

static NDIS_STATUS FilterAttach(NDIS_HANDLE NdisFilterHandle, NDIS_HANDLE FilterDriverContext, PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters)
{
    UNREFERENCED_PARAMETER(FilterDriverContext);
    UNREFERENCED_PARAMETER(AttachParameters);
    PMS_FILTER p = (PMS_FILTER)NdisAllocateMemoryWithTagPriority(NdisFilterHandle, sizeof(MS_FILTER), FILTER_ALLOC_TAG, LowPoolPriority);
    if (!p) return NDIS_STATUS_RESOURCES;
    RtlZeroMemory(p, sizeof(*p));
    p->FilterHandle = NdisFilterHandle;
    p->TrackReceives = TRUE;
    p->TrackSends = TRUE;
    FILTER_INIT_LOCK(&p->Lock);

    NDIS_FILTER_ATTRIBUTES attrs;
    RtlZeroMemory(&attrs, sizeof(attrs));
    attrs.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
    attrs.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
    attrs.Header.Size = sizeof(attrs);
    attrs.Flags = 0;
    NDIS_DECLARE_FILTER_MODULE_CONTEXT(MS_FILTER);
    NDIS_STATUS s = NdisFSetAttributes(NdisFilterHandle, p, &attrs);
    if (s != NDIS_STATUS_SUCCESS) {
        NdisFreeMemory(p, 0, 0);
        return s;
    }
    p->State = 1;
    return NDIS_STATUS_SUCCESS;
}

static VOID FilterDetach(NDIS_HANDLE FilterModuleContext)
{
    PMS_FILTER p = (PMS_FILTER)FilterModuleContext;
    if (p) {
        FILTER_FREE_LOCK(&p->Lock);
        NdisFreeMemory(p, 0, 0);
    }
}

static NDIS_STATUS FilterRestart(NDIS_HANDLE FilterModuleContext, PNDIS_FILTER_RESTART_PARAMETERS RestartParameters)
{
    UNREFERENCED_PARAMETER(FilterModuleContext);
    UNREFERENCED_PARAMETER(RestartParameters);
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS FilterPause(NDIS_HANDLE FilterModuleContext, PNDIS_FILTER_PAUSE_PARAMETERS PauseParameters)
{
    UNREFERENCED_PARAMETER(FilterModuleContext);
    UNREFERENCED_PARAMETER(PauseParameters);
    return NDIS_STATUS_SUCCESS;
}

static VOID FilterSendNetBufferLists(NDIS_HANDLE FilterModuleContext, PNET_BUFFER_LIST NetBufferLists, NDIS_PORT_NUMBER PortNumber, ULONG SendFlags)
{
    UNREFERENCED_PARAMETER(FilterModuleContext);
    UNREFERENCED_PARAMETER(PortNumber);
    NdisFSendNetBufferLists(((PMS_FILTER)FilterModuleContext)->FilterHandle, NetBufferLists, PortNumber, SendFlags);
}

static VOID FilterSendNetBufferListsComplete(NDIS_HANDLE FilterModuleContext, PNET_BUFFER_LIST NetBufferLists, ULONG SendCompleteFlags)
{
    UNREFERENCED_PARAMETER(FilterModuleContext);
    NdisFSendNetBufferListsComplete(((PMS_FILTER)FilterModuleContext)->FilterHandle, NetBufferLists, SendCompleteFlags);
}

static VOID FilterReturnNetBufferLists(NDIS_HANDLE FilterModuleContext, PNET_BUFFER_LIST NetBufferLists, ULONG ReturnFlags)
{
    UNREFERENCED_PARAMETER(FilterModuleContext);
    NdisFReturnNetBufferLists(((PMS_FILTER)FilterModuleContext)->FilterHandle, NetBufferLists, ReturnFlags);
}

// --- Hot path IPv4 parse + whitelist decision (log only) ---
static SIZE_T TlCopyFromNB(_In_ NET_BUFFER* nb, _Out_writes_bytes_(len) UCHAR* dst, _In_ SIZE_T len)
{
    SIZE_T copied = 0;
    PMDL mdl = NET_BUFFER_FIRST_MDL(nb);
    ULONG offset = NET_BUFFER_DATA_OFFSET(nb);

    while (mdl && copied < len) {
        PUCHAR va = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
        if (!va) break;
        ULONG mdlLen = MmGetMdlByteCount(mdl);
        ULONG mdlOff = MmGetMdlByteOffset(mdl);

        if (offset >= mdlLen) { offset -= mdlLen; mdl = mdl->Next; continue; }

        ULONG avail = mdlLen - offset;
        ULONG chunk = (ULONG)min(len - copied, (SIZE_T)avail);
        RtlCopyMemory(dst + copied, va + mdlOff + offset, chunk);
        copied += chunk;
        offset = 0;
        mdl = mdl->Next;
    }
    return copied;
}

static __forceinline USHORT TL_NTOHS(USHORT x){ return (USHORT)((x<<8)|(x>>8)); }

static VOID FilterReceiveNetBufferLists(NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG NumberOfNetBufferLists,
    ULONG ReceiveFlags)
{
    UNREFERENCED_PARAMETER(FilterModuleContext);
    UNREFERENCED_PARAMETER(PortNumber);
    UNREFERENCED_PARAMETER(NumberOfNetBufferLists);

    //BOOLEAN Dispatch = NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags);

    for (PNET_BUFFER_LIST nbl = NetBufferLists; nbl; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl)) {
        for (PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb; nb = NET_BUFFER_NEXT_NB(nb)) {
            UCHAR hdr[80];
            PVOID p = NdisGetDataBuffer(nb, sizeof(hdr), hdr, 1, 0);
            if (!p) {
                SIZE_T copied = TlCopyFromNB(nb, hdr, sizeof(hdr));
                if (copied < 34) continue;
                p = hdr;
            }
            const UCHAR* b = (const UCHAR*)p;
            if (nb->DataLength < 34) continue;

            UINT off = 12;
            USHORT et = (USHORT)((b[off]<<8)|b[off+1]); off+=2;
            if (et==0x8100 || et==0x88A8) { if (nb->DataLength < off+4) continue; off+=2; et=(USHORT)((b[off]<<8)|b[off+1]); off+=2; }

            if (et == 0x0800) { // IPv4
                if (nb->DataLength < off+20) goto indicate;
                const UCHAR* ip = b + off;
                if ((ip[0]>>4) != 4) goto indicate;
                UCHAR ihl = (ip[0] & 0x0F) * 4; if (ihl < 20 || nb->DataLength < off+ihl) goto indicate;
                UCHAR proto = ip[9];
                ULONG dstNbo = *(ULONG*)(ip + 16); // NBO
                const UCHAR* l4 = ip + ihl;
                USHORT dportNbo = 0;
                if (nb->DataLength >= (SIZE_T)(l4 - b) + 4) dportNbo = *(USHORT*)(l4 + 2); // NBO

                BOOLEAN allow = TlWhitelistMatchV4(dstNbo, dportNbo, proto);
                TL_DECISION_V4 d;
                d.DstIpV4 = dstNbo;
                d.DstPort = TL_NTOHS(dportNbo);
                d.Proto = proto;
                d.Allow = allow ? 1 : 0;
                TlRingPushDecision(&d);

                // TODO: if (!allow) drop packet here instead of indicating up.
            }
        }
    }

indicate:
    NdisFIndicateReceiveNetBufferLists(((PMS_FILTER)FilterModuleContext)->FilterHandle,
                                       NetBufferLists, PortNumber, NumberOfNetBufferLists, ReceiveFlags);
}

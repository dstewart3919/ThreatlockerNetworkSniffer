#ifndef _FILT_H
#define _FILT_H

#include <ndis.h>
#include "flt_dbg.h"
#include "filteruser.h"

// Pool tags
#define FILTER_REQUEST_ID          'RTLF'
#define FILTER_ALLOC_TAG           'tliF'
#define FILTER_TAG                 'dnTF'

// Use build-system NDIS contract
#define FILTER_MAJOR_NDIS_VERSION   NDIS_FILTER_MAJOR_VERSION
#define FILTER_MINOR_NDIS_VERSION   NDIS_FILTER_MINOR_VERSION

// Global objects (defined in filter.c)
extern NDIS_HANDLE         FilterDriverHandle; // NDIS handle for filter driver
extern NDIS_HANDLE         FilterDriverObject;
extern NDIS_HANDLE         NdisFilterDeviceHandle; // device handle from NdisRegisterDeviceEx
extern PDEVICE_OBJECT      NdisDeviceObject;

// Device/link names (+ service name) must match INF
#define FILTER_FRIENDLY_NAME        L"NDIS Sample LightWeight Filter"
#define FILTER_UNIQUE_NAME          L"{5cbf81bd-5055-47cd-9055-a76b2b4e3697}"
#define FILTER_SERVICE_NAME         L"NDISLWF"

#define LINKNAME_STRING             L"\\DosDevices\\NDISLWF"
#define NTDEVICE_STRING             L"\\Device\\NDISLWF"

typedef NDIS_SPIN_LOCK      FILTER_LOCK;
typedef PNDIS_SPIN_LOCK     PFILTER_LOCK;

#define FILTER_INIT_LOCK(_pLock)      NdisAllocateSpinLock(_pLock)
#define FILTER_FREE_LOCK(_pLock)      NdisFreeSpinLock(_pLock)
#define FILTER_ACQUIRE_LOCK(_pLock, Dispatch) do { if (Dispatch) NdisDprAcquireSpinLock(_pLock); else NdisAcquireSpinLock(_pLock);} while(0)
#define FILTER_RELEASE_LOCK(_pLock, Dispatch) do { if (Dispatch) NdisDprReleaseSpinLock(_pLock); else NdisReleaseSpinLock(_pLock);} while(0)

// ---------------- ThreatLocker whitelist/decision ring ----------------

#define TL_HASH_BUCKETS  1024u
#define TL_RING_CAPACITY 4096u

typedef struct _TL_WL_NODE {
    struct _TL_WL_NODE* Next;
    ULONG  DstIpV4;  // NBO
    USHORT DstPort;  // NBO
    UCHAR  Proto;    // 0=any,6,17
} TL_WL_NODE;

typedef struct _TL_DECISION_RING {
    TL_DECISION_V4* Buf;     // NonPaged pool array [TL_RING_CAPACITY]
    volatile ULONG  Head;    // producer
    volatile ULONG  Tail;    // consumer
} TL_DECISION_RING;

NTSTATUS TlWhitelistInit(VOID);
VOID     TlWhitelistFree(VOID);
NTSTATUS TlWhitelistReplace(_In_reads_bytes_(len) const TL_SET_WHITELIST* wl, _In_ ULONG len);
BOOLEAN  TlWhitelistMatchV4(_In_ ULONG dstIpNbo, _In_ USHORT dstPortNbo, _In_ UCHAR proto);

NTSTATUS TlRingInit(VOID);
VOID     TlRingFree(VOID);
VOID     TlRingPushDecision(_In_ const TL_DECISION_V4* d);
ULONG    TlRingPopBatch(_Out_writes_(max) TL_DECISION_V4* out, _In_ ULONG max);

// Device registration / dispatch (device.c)
NDIS_STATUS FilterRegisterDevice(VOID);
VOID        FilterDeregisterDevice(VOID);
DRIVER_DISPATCH FilterDispatch;
DRIVER_DISPATCH FilterDeviceIoControl;

#endif // _FILT_H

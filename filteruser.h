//
//    Copyright (C) Microsoft.  All rights reserved.
//    (Augmented for ThreatLockerNetworkSniffer)
//
#ifndef __FILTERUSER_H__
#define __FILTERUSER_H__

#include <devioctl.h>

// Keep sample IOCTL macro
#define _NDIS_CONTROL_CODE(request,method) \
            CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, request, method, FILE_ANY_ACCESS)

// --- Sample's existing IOCTLs (kept for compatibility) ---
#define IOCTL_FILTER_RESTART_ALL            _NDIS_CONTROL_CODE(0, METHOD_BUFFERED)
#define IOCTL_FILTER_RESTART_ONE_INSTANCE   _NDIS_CONTROL_CODE(1, METHOD_BUFFERED)
#define IOCTL_FILTER_ENUERATE_ALL_INSTANCES _NDIS_CONTROL_CODE(2, METHOD_BUFFERED)
#define IOCTL_FILTER_ENUMERATE_ALL_INSTANCES IOCTL_FILTER_ENUERATE_ALL_INSTANCES
#define IOCTL_FILTER_QUERY_ALL_STAT         _NDIS_CONTROL_CODE(3, METHOD_BUFFERED)
#define IOCTL_FILTER_CLEAR_ALL_STAT         _NDIS_CONTROL_CODE(4, METHOD_BUFFERED)
#define IOCTL_FILTER_SET_OID_VALUE          _NDIS_CONTROL_CODE(5, METHOD_BUFFERED)
#define IOCTL_FILTER_QUERY_OID_VALUE        _NDIS_CONTROL_CODE(6, METHOD_BUFFERED)
#define IOCTL_FILTER_CANCEL_REQUEST         _NDIS_CONTROL_CODE(7, METHOD_BUFFERED)
#define IOCTL_FILTER_READ_DRIVER_CONFIG     _NDIS_CONTROL_CODE(8, METHOD_BUFFERED)
#define IOCTL_FILTER_WRITE_DRIVER_CONFIG    _NDIS_CONTROL_CODE(9, METHOD_BUFFERED)
#define IOCTL_FILTER_READ_ADAPTER_CONFIG    _NDIS_CONTROL_CODE(10, METHOD_BUFFERED)
#define IOCTL_FILTER_WRITE_ADAPTER_CONFIG   _NDIS_CONTROL_CODE(11, METHOD_BUFFERED)
#define IOCTL_FILTER_READ_INSTANCE_CONFIG   _NDIS_CONTROL_CODE(12, METHOD_BUFFERED)
#define IOCTL_FILTER_WRITE_INSTANCE_CONFIG  _NDIS_CONTROL_CODE(13, METHOD_BUFFERED)

// --- ThreatLocker additions ---
#define IOCTL_TL_SET_WHITELIST  _NDIS_CONTROL_CODE(100, METHOD_BUFFERED)
#define IOCTL_TL_GET_DECISIONS  _NDIS_CONTROL_CODE(101, METHOD_BUFFERED)

#pragma pack(push, 1)
typedef struct _TL_ENTRY_V4 {
    ULONG  DstIpV4;   // network byte order
    USHORT DstPort;   // network byte order
    UCHAR  Proto;     // 0=any, 6=TCP, 17=UDP
    UCHAR  Reserved;
} TL_ENTRY_V4;

typedef struct _TL_SET_WHITELIST {
    ULONG Count;      // number of TL_ENTRY_V4 immediately following
    // TL_ENTRY_V4 Items[Count];
} TL_SET_WHITELIST;

typedef struct _TL_DECISION_V4 {
    ULONG  DstIpV4;   // network byte order (for printing user-mode can ntohl)
    USHORT DstPort;   // host order (for convenience)
    UCHAR  Proto;     // 6/17/other
    UCHAR  Allow;     // 1=whitelisted, 0=not
} TL_DECISION_V4;

typedef struct _TL_GET_DECISIONS {
    ULONG MaxItems;   // IN: capacity of Items[]
    ULONG OutCount;   // OUT: actual number returned
    // TL_DECISION_V4 Items[OutCount];
} TL_GET_DECISIONS;
#pragma pack(pop)

#endif //__FILTERUSER_H__

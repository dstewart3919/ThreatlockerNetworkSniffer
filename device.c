/*++
 * Minimal device and IOCTL handlers for ThreatLockerNetworkSniffer
--*/
#include "precomp.h"

#pragma NDIS_INIT_FUNCTION(FilterRegisterDevice)

_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS FilterRegisterDevice(VOID)
{
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
    UNICODE_STRING devName, symLink;
    PDRIVER_DISPATCH DispatchTable[IRP_MJ_MAXIMUM_FUNCTION+1] = {0};
    NDIS_DEVICE_OBJECT_ATTRIBUTES devAttr;

    DEBUGP(DL_TRACE, "==>FilterRegisterDevice\n");

    DispatchTable[IRP_MJ_CREATE] = FilterDispatch;
    DispatchTable[IRP_MJ_CLEANUP] = FilterDispatch;
    DispatchTable[IRP_MJ_CLOSE] = FilterDispatch;
    DispatchTable[IRP_MJ_DEVICE_CONTROL] = FilterDeviceIoControl;

    RtlInitUnicodeString(&devName, NTDEVICE_STRING);
    RtlInitUnicodeString(&symLink, LINKNAME_STRING);

    NdisZeroMemory(&devAttr, sizeof(devAttr));
    devAttr.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
    devAttr.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    devAttr.Header.Size = sizeof(devAttr);
    devAttr.DeviceName = &devName;
    devAttr.SymbolicName = &symLink;
    devAttr.MajorFunctions = &DispatchTable[0];
    devAttr.ExtensionSize = 0; // no extension

    Status = NdisRegisterDeviceEx(
        FilterDriverHandle, &devAttr, &NdisDeviceObject, &NdisFilterDeviceHandle);

    DEBUGP(DL_TRACE, "<==FilterRegisterDevice: %x\n", Status);
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID FilterDeregisterDevice(VOID)
{
    if (NdisFilterDeviceHandle) {
        NdisDeregisterDeviceEx(NdisFilterDeviceHandle);
        NdisFilterDeviceHandle = NULL;
        NdisDeviceObject = NULL;
    }
}

_Use_decl_annotations_
NTSTATUS FilterDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static __forceinline ULONG minU(ULONG a, ULONG b){ return (a<b)?a:b; }

_Use_decl_annotations_
NTSTATUS FilterDeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG inLen  = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PUCHAR buf   = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    ULONG info   = 0;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_TL_SET_WHITELIST:
        if (inLen < sizeof(TL_SET_WHITELIST)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        Status = TlWhitelistReplace((const TL_SET_WHITELIST*)buf, inLen);
        break;

    case IOCTL_TL_GET_DECISIONS:
        if (outLen < sizeof(TL_GET_DECISIONS)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        } else {
            TL_GET_DECISIONS* hdr = (TL_GET_DECISIONS*)buf;
            ULONG space = (outLen - sizeof(TL_GET_DECISIONS)) / sizeof(TL_DECISION_V4);
            ULONG max = minU(hdr->MaxItems, space);
            ULONG n = 0;
            if (max) {
                TL_DECISION_V4* items = (TL_DECISION_V4*)(hdr + 1);
                n = TlRingPopBatch(items, max);
            }
            hdr->OutCount = n;
            info = sizeof(TL_GET_DECISIONS) + n * sizeof(TL_DECISION_V4);
            Status = STATUS_SUCCESS;
        }
        break;

    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

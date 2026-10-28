#pragma once
#include <ntddk.h>

#define FILE_DEVICE_MASS_STORAGE     0x0000002d
#define FILE_DEVICE_PHYSICAL_NETCARD 0x00000017

#define IOCTL_STORAGE_QUERY_PROPERTY \
    CTL_CODE(FILE_DEVICE_MASS_STORAGE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NDIS_QUERY_GLOBAL_STATS \
    CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, 0x0000, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define OID_802_3_PERMANENT_ADDRESS 0x01010101
#define OID_802_3_CURRENT_ADDRESS   0x01010102

#ifndef KEY_ENUMERATE_SUB_KEYS
#define KEY_ENUMERATE_SUB_KEYS 0x0008
#endif

#define StorageDeviceProperty  0
#define PropertyStandardQuery  0

typedef enum _SYSTEM_INFORMATION_CLASS { SystemBasicInformation = 0 } SYSTEM_INFORMATION_CLASS;

typedef struct _STORAGE_PROPERTY_QUERY {
    ULONG PropertyId;
    ULONG QueryType;
    UCHAR AdditionalParameters[1];
} STORAGE_PROPERTY_QUERY, *PSTORAGE_PROPERTY_QUERY;

typedef struct _STORAGE_DEVICE_DESCRIPTOR {
    ULONG   Version;
    ULONG   Size;
    UCHAR   DeviceType;
    UCHAR   DeviceTypeModifier;
    BOOLEAN RemovableMedia;
    BOOLEAN CommandQueueing;
    ULONG   VendorIdOffset;
    ULONG   ProductIdOffset;
    ULONG   ProductRevisionOffset;
    ULONG   SerialNumberOffset;
    ULONG   BusType;
    ULONG   RawPropertiesLength;
    UCHAR   RawDeviceProperties[1];
} STORAGE_DEVICE_DESCRIPTOR, *PSTORAGE_DEVICE_DESCRIPTOR;

extern POBJECT_TYPE *IoDriverObjectType;
NTSTATUS NTAPI ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes,
    PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID *Object);

static __inline size_t VnStrLenA(const char* s) { size_t n = 0; while (s[n]) n++; return n; }
static __inline size_t VnStrLenW(const wchar_t* s) { size_t n = 0; while (s[n]) n++; return n; }

// VnSpoofer.sys - spoofer HWID kernel, 100% en memoire
#include <ntddk.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include "ntdefs.h"
#include "hde64.h"

#define DEV_NAME  L"\\Device\\VnSpoofer"
#define SYM_NAME  L"\\DosDevices\\VnSpoofer"
#define BK_KEY    L"\\Registry\\Machine\\SOFTWARE\\VnSpoofer"
#define BIOS_KEY  L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS"
#define GPU_CLASS L"{4d36e968-e325-11ce-bfc1-08002be10318}"

#define IOCTL_APPLY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REVERT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STATE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _SFTI { ULONG ProviderSignature; ULONG Action; ULONG TableID; ULONG TableBufferLength; UCHAR TableBuffer[1]; } SFTI, *PSFTI;
#define SystemFirmwareTableInformation ((SYSTEM_INFORMATION_CLASS)76)

#pragma pack(push, 1)
typedef struct _SPOOF_CFG {
    ULONG Flags;
    CHAR  DiskSerial[24];
    ULONG VolumeSerial;
    UCHAR Mac[6];
    UCHAR Uuid[16];
    CHAR  BoardSerial[24];
    CHAR  BiosSerial[24];
    CHAR  SysProduct[24];
    CHAR  MachineGuid[40];
} SPOOF_CFG, *PSPOOF_CFG;
#pragma pack(pop)

#define SPOOF_DISK 0x01
#define SPOOF_VOLUME 0x02
#define SPOOF_SMBIOS 0x04
#define SPOOF_MAC 0x08
#define SPOOF_GUID 0x10
#define SPOOF_GPU 0x20

static SPOOF_CFG g_Cfg;
static BOOLEAN g_Applied;
static PVOID g_Nqsi;
static PVOID g_NdiCf;
static UCHAR g_EnumBuf[600], g_EnumBuf2[600];

typedef struct _DETOUR { PVOID Target, Hook; PUCHAR Tramp; UCHAR Stolen[24]; ULONG Len; BOOLEAN Active; } DETOUR;
static DETOUR g_DtNdi, g_DtNqsi;

static KIRQL g_Irql;
static __forceinline void WpOff() { g_Irql = KeRaiseIrqlToDpcLevel(); __writecr0(__readcr0() & ~0x10000); }
static __forceinline void WpOn() { __writecr0(__readcr0() | 0x10000); KeLowerIrql(g_Irql); }

static NTSTATUS DetourInstall(DETOUR* d, PVOID t, PVOID h)
{
    hde64s hs; ULONG len = 0, off = 0;
    d->Target = t; d->Hook = h;
    d->Tramp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 64, 'rtnD');
    if (!d->Tramp) return STATUS_INSUFFICIENT_RESOURCES;
    while (len < 14) {
        if (!hde64_disasm((PUCHAR)t + len, &hs) || !hs.len) return STATUS_UNSUCCESSFUL;
        len += hs.len;
        if (len > 20) break;
    }
    d->Len = len;
    RtlCopyMemory(d->Stolen, t, len);
    RtlCopyMemory(d->Tramp, t, len);
    while (off < len) {
        hde64_disasm(d->Stolen + off, &hs);
        if (hs.flags & F_RELATIVE) {
            ULONGLONG abs = (ULONGLONG)((PUCHAR)t + off + hs.len + hs.disp.disp32);
            *(PLONG)(d->Tramp + off + (ULONG)FIELD_OFFSET(hde64s, disp)) = (LONG)(abs - (ULONGLONG)(d->Tramp + off + hs.len));
        }
        off += hs.len;
    }
    PUCHAR j = d->Tramp + len;
    j[0] = 0xFF; j[1] = 0x25; *(PULONG)(j + 2) = 0; *(PVOID*)(j + 6) = (PUCHAR)t + len;
    WpOff();
    PUCHAR p = (PUCHAR)t;
    p[0] = 0x48; p[1] = 0xB8; *(PVOID*)(p + 2) = h; p[10] = 0xFF; p[11] = 0xE0;
    for (ULONG i = 12; i < len; i++) p[i] = 0x90;
    WpOn();
    d->Active = TRUE;
    return STATUS_SUCCESS;
}

static void DetourRemove(DETOUR* d)
{
    if (!d->Active) return;
    WpOff(); RtlCopyMemory(d->Target, d->Stolen, d->Len); WpOn();
    ExFreePoolWithTag(d->Tramp, 'rtnD'); d->Active = FALSE;
}

typedef NTSTATUS (*PFN_DISPATCH)(PDEVICE_OBJECT, PIRP);
typedef NTSTATUS (*PFN_NDICF)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS (*PFN_NQSI)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

static PFN_DISPATCH g_OrigDisk, g_OrigVol;
static BOOLEAN g_HookDisk, g_HookVol, g_HookMac, g_HookSmb, g_HookGpu;

static NTSTATUS HookDrv(PCWSTR name, ULONG major, PVOID nf, PVOID* of)
{
    UNICODE_STRING n; PDRIVER_OBJECT d = NULL;
    RtlInitUnicodeString(&n, name);
    NTSTATUS st = ObReferenceObjectByName(&n, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&d);
    if (!NT_SUCCESS(st)) return st;
    *of = d->MajorFunction[major];
    d->MajorFunction[major] = (PDRIVER_DISPATCH)nf;
    ObDereferenceObject(d);
    return STATUS_SUCCESS;
}

static NTSTATUS DiskDone(PDEVICE_OBJECT dev, PIRP irp, PVOID c)
{
    UNREFERENCED_PARAMETER(dev); UNREFERENCED_PARAMETER(c);
    if (!NT_SUCCESS(irp->IoStatus.Status)) return STATUS_SUCCESS;
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    if (sp->Parameters.DeviceIoControl.IoControlCode != IOCTL_STORAGE_QUERY_PROPERTY) return STATUS_SUCCESS;
    PSTORAGE_PROPERTY_QUERY q = (PSTORAGE_PROPERTY_QUERY)irp->AssociatedIrp.SystemBuffer;
    if (!q || q->PropertyId != StorageDeviceProperty || q->QueryType != PropertyStandardQuery) return STATUS_SUCCESS;
    PSTORAGE_DEVICE_DESCRIPTOR dd = (PSTORAGE_DEVICE_DESCRIPTOR)irp->AssociatedIrp.SystemBuffer;
    ULONG out = sp->Parameters.DeviceIoControl.OutputBufferLength;
    if (dd->SerialNumberOffset && dd->SerialNumberOffset < out)
        RtlStringCchCopyNA((PCHAR)dd + dd->SerialNumberOffset, out - dd->SerialNumberOffset, g_Cfg.DiskSerial, 20);
    return STATUS_SUCCESS;
}

static NTSTATUS HookDisk(PDEVICE_OBJECT dev, PIRP irp)
{
    if (IoGetCurrentIrpStackLocation(irp)->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        if (irp->CurrentLocation > 0) IoCopyCurrentIrpStackLocationToNext(irp);
        else *IoGetNextIrpStackLocation(irp) = *IoGetCurrentIrpStackLocation(irp);
        IoSetCompletionRoutine(irp, DiskDone, NULL, TRUE, TRUE, TRUE);
    }
    return g_OrigDisk(dev, irp);
}

static NTSTATUS VolDone(PDEVICE_OBJECT dev, PIRP irp, PVOID c)
{
    UNREFERENCED_PARAMETER(dev); UNREFERENCED_PARAMETER(c);
    if (NT_SUCCESS(irp->IoStatus.Status)) {
        PFILE_FS_VOLUME_INFORMATION v = (PFILE_FS_VOLUME_INFORMATION)irp->AssociatedIrp.SystemBuffer;
        if (v) v->VolumeSerialNumber = g_Cfg.VolumeSerial;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS HookVol(PDEVICE_OBJECT dev, PIRP irp)
{
    if (irp->CurrentLocation > 0) IoCopyCurrentIrpStackLocationToNext(irp);
    else *IoGetNextIrpStackLocation(irp) = *IoGetCurrentIrpStackLocation(irp);
    IoSetCompletionRoutine(irp, VolDone, NULL, TRUE, TRUE, TRUE);
    return g_OrigVol(dev, irp);
}

static NTSTATUS HookNdi(HANDLE h, HANDLE ev, PIO_APC_ROUTINE a, PVOID ac, PIO_STATUS_BLOCK io, ULONG code, PVOID in, ULONG il, PVOID out, ULONG ol)
{
    NTSTATUS st = ((PFN_NDICF)g_NdiCf)(h, ev, a, ac, io, code, in, il, out, ol);
    if (NT_SUCCESS(st) && code == IOCTL_NDIS_QUERY_GLOBAL_STATS && in && il >= 4 && out && ol >= 6) {
        ULONG oid = *(PULONG)in;
        if (oid == OID_802_3_CURRENT_ADDRESS || oid == OID_802_3_PERMANENT_ADDRESS) RtlCopyMemory(out, g_Cfg.Mac, 6);
    }
    return st;
}

static void SmbStr(PUCHAR hdr, PUCHAR end, UCHAR idx, const CHAR* val)
{
    if (!idx) return;
    PUCHAR p = hdr + 4 + hdr[1];
    for (UCHAR i = 1; i <= idx; i++) {
        if (p >= end) return;
        if (i == idx) { RtlStringCchCopyNA((CHAR*)p, VnStrLenA((CHAR*)p) + 1, val, VnStrLenA((CHAR*)p)); return; }
        p += VnStrLenA((CHAR*)p) + 1;
    }
}

static void PatchSmbios(PSFTI fi)
{
    if (fi->TableBufferLength < 12) return;
    PUCHAR p = fi->TableBuffer + 8, end = fi->TableBuffer + fi->TableBufferLength;
    while (p + 4 < end) {
        UCHAR t = p[0], sl = p[1];
        PUCHAR nx = p + 4 + sl;
        if (nx >= end) break;
        if (t == 1 && sl >= 0x19) { RtlCopyMemory(p + 8, g_Cfg.Uuid, 16); SmbStr(p, end, p[5], g_Cfg.SysProduct); }
        else if (t == 2 && sl >= 8) SmbStr(p, end, p[7], g_Cfg.BoardSerial);
        else if (t == 0 && sl >= 8) SmbStr(p, end, p[7], g_Cfg.BiosSerial);
        while (nx + 1 < end && !(nx[0] == 0 && nx[1] == 0)) nx++;
        p = nx + 2;
    }
}

static NTSTATUS HookNqsi(SYSTEM_INFORMATION_CLASS c, PVOID buf, ULONG len, PULONG ret)
{
    NTSTATUS st = ((PFN_NQSI)g_Nqsi)(c, buf, len, ret);
    if (NT_SUCCESS(st) && c == SystemFirmwareTableInformation && buf) {
        PSFTI fi = (PSFTI)buf;
        if (fi->ProviderSignature == 'RSMB' && fi->TableBufferLength) PatchSmbios(fi);
    }
    return st;
}

static NTSTATUS RegSz(PCWSTR path, PCWSTR val, PCWSTR data)
{
    return RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, path, val, REG_SZ, (PVOID)data, ((ULONG)VnStrLenW(data) + 1) * sizeof(WCHAR));
}

static NTSTATUS RegRead(PCWSTR path, PCWSTR val, PWSTR out, ULONG cch)
{
    RTL_QUERY_REGISTRY_TABLE tab[2] = {0};
    tab[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    tab[0].Name = val; tab[0].EntryContext = out;
    tab[0].DefaultType = REG_SZ; tab[0].DefaultData = L""; tab[0].DefaultLength = 0;
    UNREFERENCED_PARAMETER(cch);
    return RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, path, tab, NULL, NULL);
}

static void GuidApply()
{
    WCHAR cur[64] = {0};
    if (NT_SUCCESS(RegRead(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", cur, 64)) && cur[0])
        RegSz(BK_KEY, L"GuidBackup", cur);
    WCHAR w[64] = {0};
    for (int i = 0; i < 40 && g_Cfg.MachineGuid[i]; i++) w[i] = (WCHAR)g_Cfg.MachineGuid[i];
    RegSz(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", w);
}

static void GuidRevert()
{
    WCHAR cur[64] = {0};
    if (NT_SUCCESS(RegRead(BK_KEY, L"GuidBackup", cur, 64)) && cur[0]) {
        RegSz(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", cur);
        RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, BK_KEY, L"GuidBackup");
    }
}

static void BiosMirrorApply()
{
    WCHAR w[32] = {0};
    for (int i = 0; i < 24 && g_Cfg.BoardSerial[i]; i++) w[i] = (WCHAR)g_Cfg.BoardSerial[i];
    RegSz(BIOS_KEY, L"BaseBoardSerialNumber", w); RtlZeroMemory(w, sizeof(w));
    for (int i = 0; i < 24 && g_Cfg.SysProduct[i]; i++) w[i] = (WCHAR)g_Cfg.SysProduct[i];
    RegSz(BIOS_KEY, L"SystemProductName", w); RegSz(BIOS_KEY, L"BaseBoardProduct", w); RtlZeroMemory(w, sizeof(w));
    for (int i = 0; i < 24 && g_Cfg.BiosSerial[i]; i++) w[i] = (WCHAR)g_Cfg.BiosSerial[i];
    RegSz(BIOS_KEY, L"BIOSVersion", w);
}

static NTSTATUS RegCopyVals(HANDLE src, HANDLE dst)
{
    ULONG sz = 0, i = 0;
    ZwEnumerateValueKey(src, 0, KeyValueFullInformation, NULL, 0, &sz);
    if (!sz) return STATUS_SUCCESS;
    PKEY_VALUE_FULL_INFORMATION kv = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, sz, 'vpyR');
    if (!kv) return STATUS_INSUFFICIENT_RESOURCES;
    for (;; i++) {
        if (!NT_SUCCESS(ZwEnumerateValueKey(src, i, KeyValueFullInformation, kv, sz, &sz))) break;
        {
            UNICODE_STRING vn;
            vn.Buffer = kv->Name;
            vn.Length = (USHORT)kv->NameLength;
            vn.MaximumLength = (USHORT)kv->NameLength;
            ZwSetValueKey(dst, &vn, 0, kv->Type, (PUCHAR)kv + kv->DataOffset, kv->DataLength);
        }
    }
    ExFreePoolWithTag(kv, 'vpyR');
    return STATUS_SUCCESS;
}

static HANDLE OpenAbs(PCWSTR path, ACCESS_MASK acc, HANDLE parent)
{
    UNICODE_STRING u; RtlInitUnicodeString(&u, path);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, parent, NULL);
    HANDLE h = NULL;
    if (!NT_SUCCESS(ZwOpenKey(&h, acc, &oa))) return NULL;
    return h;
}

static HANDLE CreateAbs(PCWSTR path, HANDLE parent)
{
    UNICODE_STRING u; RtlInitUnicodeString(&u, path);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, parent, NULL);
    HANDLE h = NULL;
    if (!NT_SUCCESS(ZwCreateKey(&h, KEY_ALL_ACCESS, &oa, 0, NULL, 0, NULL))) return NULL;
    return h;
}

static NTSTATUS GpuMove(PCWSTR from, PCWSTR to)
{
    HANDLE sh = OpenAbs(from, KEY_ALL_ACCESS, NULL);
    if (!sh) return STATUS_UNSUCCESSFUL;
    HANDLE th = CreateAbs(to, NULL);
    if (!th) { ZwClose(sh); return STATUS_UNSUCCESSFUL; }

    RegCopyVals(sh, th);

    HANDLE ph = OpenAbs(L"Device Parameters", KEY_ALL_ACCESS, sh);
    if (ph) {
        HANDLE ph2 = CreateAbs(L"Device Parameters", th);
        if (ph2) { RegCopyVals(ph, ph2); ZwClose(ph2); }
        ZwDeleteKey(ph); ZwClose(ph);
    }
    ZwClose(th);
    ZwDeleteKey(sh);
    ZwClose(sh);
    return STATUS_SUCCESS;
}

static NTSTATUS GpuApply()
{
    WCHAR base[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\PCI";
    HANDLE root = OpenAbs(base, KEY_ENUMERATE_SUB_KEYS, NULL);
    if (!root) return STATUS_UNSUCCESSFUL;

    ULONG n = 0, i = 0, saved = 0;
    WCHAR tmp[700], dst[720], cnt[8];
    while (NT_SUCCESS(ZwEnumerateKey(root, i++, KeyBasicInformation, g_EnumBuf, 512, &n))) {
        PKEY_BASIC_INFORMATION kb = (PKEY_BASIC_INFORMATION)g_EnumBuf;
        if (kb->Name.Length < 8 || kb->Name.Buffer[0] != L'V' || kb->Name.Buffer[1] != L'E' || kb->Name.Buffer[2] != L'N' || kb->Name.Buffer[3] != L'_') continue;

        RtlStringCchPrintfW(tmp, 700, L"%s\\%wZ", base, &kb->Name);
        WCHAR cls[64] = {0};
        if (!NT_SUCCESS(RegRead(tmp, L"ClassGUID", cls, 64))) continue;
        { UNICODE_STRING ua, ub; RtlInitUnicodeString(&ua, cls); RtlInitUnicodeString(&ub, GPU_CLASS);
          if (!RtlEqualUnicodeString(&ua, &ub, TRUE)) continue; }

        HANDLE dh = OpenAbs(tmp, KEY_ENUMERATE_SUB_KEYS, NULL);
        if (!dh) continue;

        ULONG m = 0, k = 0;
        while (NT_SUCCESS(ZwEnumerateKey(dh, k++, KeyBasicInformation, g_EnumBuf2, 512, &m))) {
            PKEY_BASIC_INFORMATION ib = (PKEY_BASIC_INFORMATION)g_EnumBuf2;
            WCHAR src[760];
            RtlStringCchPrintfW(src, 760, L"%s\\%wZ", tmp, &ib->Name);
            RtlStringCchPrintfW(dst, 720, L"%s-SPOOF", src);
            if (NT_SUCCESS(GpuMove(src, dst))) {
                RtlStringCchPrintfW(cnt, 8, L"%lu", saved++);
                RegSz(BK_KEY, cnt, src);
            }
        }
        ZwClose(dh);
    }
    ZwClose(root);
    g_HookGpu = TRUE;
    return STATUS_SUCCESS;
}

static void GpuRevert()
{
    WCHAR src[760], back[720], cnt[8];
    for (ULONG i = 0; i < 32; i++) {
        RtlStringCchPrintfW(cnt, 8, L"%lu", i);
        WCHAR val[760] = {0};
        if (!NT_SUCCESS(RegRead(BK_KEY, cnt, val, 760)) || !val[0]) continue;
        RtlStringCchPrintfW(src, 760, L"%s", val);
        RtlStringCchPrintfW(back, 720, L"%s-SPOOF", src);
        GpuMove(back, src);
        RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, BK_KEY, cnt);
    }
    g_HookGpu = FALSE;
}

static NTSTATUS DoApply(PSPOOF_CFG c)
{
    if (g_Applied) return STATUS_ALREADY_REGISTERED;
    RtlCopyMemory(&g_Cfg, c, sizeof(SPOOF_CFG));

    if (c->Flags & SPOOF_DISK)
        if (NT_SUCCESS(HookDrv(L"\\Driver\\disk", IRP_MJ_DEVICE_CONTROL, HookDisk, (PVOID*)&g_OrigDisk))) g_HookDisk = TRUE;

    if (c->Flags & SPOOF_VOLUME)
        if (NT_SUCCESS(HookDrv(L"\\FileSystem\\Ntfs", IRP_MJ_QUERY_VOLUME_INFORMATION, HookVol, (PVOID*)&g_OrigVol))) g_HookVol = TRUE;

    if (c->Flags & SPOOF_MAC) {
        UNICODE_STRING n; RtlInitUnicodeString(&n, L"NtDeviceIoControlFile");
        g_NdiCf = MmGetSystemRoutineAddress(&n);
        if (g_NdiCf && NT_SUCCESS(DetourInstall(&g_DtNdi, g_NdiCf, HookNdi))) g_HookMac = TRUE;
    }
    if (c->Flags & SPOOF_SMBIOS) {
        UNICODE_STRING n; RtlInitUnicodeString(&n, L"NtQuerySystemInformation");
        g_Nqsi = MmGetSystemRoutineAddress(&n);
        if (g_Nqsi && NT_SUCCESS(DetourInstall(&g_DtNqsi, g_Nqsi, HookNqsi))) g_HookSmb = TRUE;
        BiosMirrorApply();
    }
    if (c->Flags & SPOOF_GUID) GuidApply();
    if (c->Flags & SPOOF_GPU) GpuApply();

    g_Applied = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS DoRevert()
{
    if (!g_Applied) return STATUS_UNSUCCESSFUL;
    if (g_HookGpu) GpuRevert();
    if (g_HookSmb) { DetourRemove(&g_DtNqsi); g_HookSmb = FALSE; }
    if (g_HookMac) { DetourRemove(&g_DtNdi); g_HookMac = FALSE; }
    if (g_HookVol) { HookDrv(L"\\FileSystem\\Ntfs", IRP_MJ_QUERY_VOLUME_INFORMATION, g_OrigVol, (PVOID*)&g_OrigVol); g_HookVol = FALSE; }
    if (g_HookDisk) { HookDrv(L"\\Driver\\disk", IRP_MJ_DEVICE_CONTROL, g_OrigDisk, (PVOID*)&g_OrigDisk); g_HookDisk = FALSE; }
    if (g_Cfg.Flags & SPOOF_GUID) GuidRevert();
    g_Applied = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS Dispatch(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
    ULONG out = 0;
    if (sp->MajorFunction == IRP_MJ_CREATE || sp->MajorFunction == IRP_MJ_CLOSE) st = STATUS_SUCCESS;
    else if (sp->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;
        if (code == IOCTL_APPLY && sp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(SPOOF_CFG))
            st = DoApply((PSPOOF_CFG)irp->AssociatedIrp.SystemBuffer);
        else if (code == IOCTL_REVERT) st = DoRevert();
        else if (code == IOCTL_STATE && sp->Parameters.DeviceIoControl.OutputBufferLength >= 1) {
            *(PUCHAR)irp->AssociatedIrp.SystemBuffer = g_Applied ? 1 : 0; out = 1; st = STATUS_SUCCESS;
        }
    }
    irp->IoStatus.Status = st;
    irp->IoStatus.Information = out;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}

static VOID Unload(PDRIVER_OBJECT d)
{
    if (g_Applied) DoRevert();
    UNICODE_STRING s; RtlInitUnicodeString(&s, SYM_NAME);
    IoDeleteSymbolicLink(&s);
    IoDeleteDevice(d->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNREFERENCED_PARAMETER(reg);
    UNICODE_STRING n, s;
    RtlInitUnicodeString(&n, DEV_NAME);
    RtlInitUnicodeString(&s, SYM_NAME);
    PDEVICE_OBJECT dev;
    NTSTATUS st = IoCreateDevice(drv, 0, &n, FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;
    IoCreateSymbolicLink(&s, &n);
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) drv->MajorFunction[i] = Dispatch;
    drv->DriverUnload = Unload;
    dev->Flags |= DO_BUFFERED_IO;
    dev->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
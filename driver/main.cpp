// VnSpoofer.sys - spoofer HWID kernel, 100% en memoire
#include <ntddk.h>
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#include <intrin.h>
#include "ntdefs.h"
#include "hde64.h"

#define DEV_NAME  L"\\Device\\VnSpoofer"
#define SYM_NAME  L"\\DosDevices\\VnSpoofer"
#define BK_KEY    L"\\Registry\\Machine\\SOFTWARE\\VnSpoofer"
#define BIOS_KEY  L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS"
#define GPU_CLASS L"{4d36e968-e325-11ce-bfc1-08002be10318}"
#define NET_CLASS L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"
#define GPU_CLASS_KEY L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}"

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
static UCHAR g_EnumBuf[600];
static UCHAR g_EnumBuf2[600];

typedef struct _DETOUR {
    PVOID   Target;
    PVOID   Hook;
    PUCHAR  Tramp;
    UCHAR   Stolen[32];
    ULONG   Len;
    ULONG   TrampLen;
    BOOLEAN Active;
} DETOUR;

static DETOUR g_DtNdi, g_DtNqsi;

#pragma section(".text$z", read, execute)
__declspec(allocate(".text$z")) static UCHAR g_TrampPool[4][256];
static ULONG g_TrampNext = 0;

static KIRQL g_Irql;
static ULONG g_Step;
static __forceinline void WpOff() { g_Irql = KeRaiseIrqlToDpcLevel(); __writecr0(__readcr0() & ~0x10000); }
static __forceinline void WpOn()  { __writecr0(__readcr0() | 0x10000); KeLowerIrql(g_Irql); }
static void CopyA(PCHAR dst, ULONG cch, const CHAR* src, ULONG max)
{
    if (!cch) return;
    ULONG i = 0;
    while (i + 1 < cch && i < max && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = 0;
}

static void CopyW(PWSTR dst, ULONG cch, PCWSTR src, ULONG max)
{
    if (!cch) return;
    ULONG i = 0;
    while (i + 1 < cch && i < max && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = 0;
}

static void Append(PWSTR dst, ULONG cch, PCWSTR src)
{
    ULONG n = 0, i = 0;
    while (n + 1 < cch && dst[n]) n++;
    while (n + 1 < cch && src[i]) { dst[n++] = src[i++]; }
    dst[n] = 0;
}

static void AppendN(PWSTR dst, ULONG cch, PCWSTR src, ULONG chars)
{
    ULONG n = 0, i = 0;
    while (n + 1 < cch && dst[n]) n++;
    while (n + 1 < cch && i < chars && src[i]) { dst[n++] = src[i++]; }
    dst[n] = 0;
}

static void NumW(PWSTR dst, ULONG cch, ULONG v)
{
    WCHAR t[12];
    ULONG n = 0, o = 0;
    if (!v) t[n++] = L'0';
    while (v) { t[n++] = (WCHAR)(L'0' + (v % 10)); v /= 10; }
    while (n && o + 1 < cch) dst[o++] = t[--n];
    dst[o] = 0;
}

static void DbgDw(PCWSTR name, ULONG v)
{
    UNICODE_STRING u, vn;
    OBJECT_ATTRIBUTES oa;
    HANDLE h;

    RtlInitUnicodeString(&u, BK_KEY);
    InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateKey(&h, KEY_ALL_ACCESS, &oa, 0, NULL, 0, NULL))) return;
    RtlInitUnicodeString(&vn, name);
    ZwSetValueKey(h, &vn, 0, REG_DWORD, &v, sizeof(v));
    ZwClose(h);
}
static NTSTATUS WriteKernelMem(PVOID dst, PVOID src, ULONG len)
{
    PMDL  mdl;
    PVOID map;

    mdl = IoAllocateMdl(dst, len, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return STATUS_UNSUCCESSFUL;
    }

    MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    map = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (!map) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return STATUS_UNSUCCESSFUL;
    }

    RtlCopyMemory(map, src, len);
    MmUnmapLockedPages(map, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}
static BOOLEAN IsKernelPtr(PVOID p)
{
    ULONG64 v = (ULONG64)p;
    return (v >= 0xFFFF800000000000ULL);
}

static NTSTATUS DetourInstall(DETOUR* d, PVOID t, PVOID h)
{
    hde64s hs;
    ULONG  len = 0, out = 0, off, nins = 0;
    PUCHAR src, dst;
    LONG   nd;
    ULONGLONG abs;

    if (!d || !t || !h || !IsKernelPtr(t) || !IsKernelPtr(h)) return STATUS_INVALID_PARAMETER;
    if (g_TrampNext >= 4) return STATUS_INSUFFICIENT_RESOURCES; g_Step = 1;

    for (int hop = 0; hop < 4; hop++) {
        PUCHAR p = (PUCHAR)t;
        if (p[0] == 0xE9) { t = p + 5 + *(LONG*)(p + 1); if (!IsKernelPtr(t)) return STATUS_UNSUCCESSFUL; continue; }
        if (p[0] == 0xEB) { t = p + 2 + (LONG)(*(signed char*)(p + 1)); if (!IsKernelPtr(t)) return STATUS_UNSUCCESSFUL; continue; }
        break;
    }

    g_Step = 2; while (len < 14) {
        if (!hde64_disasm((PUCHAR)t + len, &hs) || hs.len == 0 || hs.len > 15) return STATUS_UNSUCCESSFUL;
        len += hs.len;
        nins++;
        if (nins > 8 || len > 24) return STATUS_UNSUCCESSFUL;
    }

    g_Step = 3; d->Target   = t;
    d->Hook     = h;
    d->Len      = len;
    d->TrampLen = 0;
    d->Active   = FALSE;
    d->Tramp    = g_TrampPool[g_TrampNext++];
    RtlZeroMemory(d->Tramp, 256);
    RtlCopyMemory(d->Stolen, t, len);

    src = (PUCHAR)t;
    dst = d->Tramp;
    off = 0;
    while (off < len) {
        UCHAR op;
        if (!hde64_disasm(src + off, &hs) || hs.len == 0) return STATUS_UNSUCCESSFUL;
        op = hs.opcode;

        if (op == 0xE9 || op == 0xE8) {
            abs = (ULONGLONG)(src + off) + hs.len + *(LONG*)(src + off + hs.len - 4);
            if (!IsKernelPtr((PVOID)abs)) return STATUS_UNSUCCESSFUL;
            nd  = (LONG)(abs - ((ULONGLONG)dst + out + hs.len));
            RtlCopyMemory(dst + out, src + off, hs.len);
            *(LONG*)(dst + out + hs.len - 4) = nd;
            out += hs.len;
        }
        else if (op == 0xEB) {
            abs = (ULONGLONG)(src + off) + hs.len + (LONG)(*(signed char*)(src + off + 1));
            if (!IsKernelPtr((PVOID)abs)) return STATUS_UNSUCCESSFUL;
            nd  = (LONG)(abs - ((ULONGLONG)dst + out + 5));
            dst[out] = 0xE9;
            *(LONG*)(dst + out + 1) = nd;
            out += 5;
        }
        else if (op >= 0x70 && op <= 0x7F) {
            abs = (ULONGLONG)(src + off) + hs.len + (LONG)(*(signed char*)(src + off + 1));
            if (!IsKernelPtr((PVOID)abs)) return STATUS_UNSUCCESSFUL;
            nd  = (LONG)(abs - ((ULONGLONG)dst + out + 6));
            dst[out] = 0x0F;
            dst[out + 1] = (UCHAR)(0x80 + (op - 0x70));
            *(LONG*)(dst + out + 2) = nd;
            out += 6;
        }
        else if (op == 0x0F && hs.opcode2 >= 0x80 && hs.opcode2 <= 0x8F) {
            abs = (ULONGLONG)(src + off) + hs.len + *(LONG*)(src + off + hs.len - 4);
            if (!IsKernelPtr((PVOID)abs)) return STATUS_UNSUCCESSFUL;
            nd  = (LONG)(abs - ((ULONGLONG)dst + out + hs.len));
            RtlCopyMemory(dst + out, src + off, hs.len);
            *(LONG*)(dst + out + hs.len - 4) = nd;
            out += hs.len;
        }
        else if ((hs.flags & F_MODRM) && hs.modrm_mod == 0 && hs.modrm_rm == 5 && hs.len >= 5) {
            abs = (ULONGLONG)(src + off) + hs.len + *(LONG*)(src + off + hs.len - 4);
            if (!IsKernelPtr((PVOID)abs)) return STATUS_UNSUCCESSFUL;
            nd  = (LONG)(abs - ((ULONGLONG)dst + out + hs.len));
            RtlCopyMemory(dst + out, src + off, hs.len);
            *(LONG*)(dst + out + hs.len - 4) = nd;
            out += hs.len;
        }
        else {
            RtlCopyMemory(dst + out, src + off, hs.len);
            out += hs.len;
        }

        if (out > 200) return STATUS_UNSUCCESSFUL;
        off += hs.len;
    }

    g_Step = 4; dst[out] = 0xFF;
    dst[out + 1] = 0x25;
    *(LONG*)(dst + out + 2) = 0;
    *(PVOID*)(dst + out + 6) = (PUCHAR)t + len;
    d->TrampLen = out + 14;

    {
        ULONG vl = 0, vc = 0, k;
        BOOLEAN bad = FALSE; g_Step = 5;
        for (k = 0; k < nins; k++) {
            hde64s vs;
            if (!hde64_disasm(dst + vl, &vs) || vs.len == 0) { bad = TRUE; break; }
            vl += vs.len;
            vc++;
        }
        if (bad || vc != nins || vl != out) return STATUS_UNSUCCESSFUL;
    }

    {
        UCHAR patch[32];
        g_Step = 6; patch[0] = 0x48;
        patch[1] = 0xB8;
        *(PVOID*)(patch + 2) = h;
        patch[10] = 0xFF;
        patch[11] = 0xE0;
        for (ULONG k = 12; k < len; k++) patch[k] = 0x90;
        if (!NT_SUCCESS(WriteKernelMem(t, patch, len))) return STATUS_UNSUCCESSFUL; g_Step = 7;
    }

    g_Step = 8; if (((PUCHAR)t)[0] != 0x48 || ((PUCHAR)t)[10] != 0xFF) {
        WriteKernelMem((PUCHAR)t, d->Stolen, len);

        return STATUS_UNSUCCESSFUL;
    }

    g_Step = 9; d->Active = TRUE;
    return STATUS_SUCCESS;
}
static void DetourRemove(DETOUR* d)
{
    if (!d || !d->Active) return;
    WriteKernelMem(d->Target, d->Stolen, d->Len);

    d->Active = FALSE;
}
typedef NTSTATUS (*PFN_DISPATCH)(PDEVICE_OBJECT, PIRP);
typedef NTSTATUS (*PFN_NDICF)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS (*PFN_NQSI)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

static PFN_DISPATCH g_OrigDisk;
static PFN_DISPATCH g_OrigVol;
static PDRIVER_OBJECT g_DrvDisk;
static PDRIVER_OBJECT g_DrvVol;
static BOOLEAN g_HookDisk, g_HookVol, g_HookMac, g_HookSmb, g_HookGpu;

static PDRIVER_OBJECT DrvOfVolume(PCWSTR name)
{
    UNICODE_STRING u;
    RtlInitUnicodeString(&u, name);
    PFILE_OBJECT fo = NULL;
    PDEVICE_OBJECT dev = NULL;
    if (!NT_SUCCESS(IoGetDeviceObjectPointer(&u, FILE_READ_ATTRIBUTES, &fo, &dev))) return NULL;
    // pas de remontee AttachedDevice : l IRP entre par le device nomme
    PDRIVER_OBJECT d = dev->DriverObject;
    ObDereferenceObject(fo);
    return d;
}

static NTSTATUS HookDrv(PDRIVER_OBJECT d, ULONG major, PVOID nf, PVOID* of)
{
    if (!d) return STATUS_UNSUCCESSFUL;
    *of = (PVOID)d->MajorFunction[major];
    d->MajorFunction[major] = (PDRIVER_DISPATCH)nf;
    return STATUS_SUCCESS;
}
static void DbgInc(PCWSTR name);

static NTSTATUS DiskDone(PDEVICE_OBJECT dev, PIRP irp, PVOID c)
{
    UNREFERENCED_PARAMETER(dev); UNREFERENCED_PARAMETER(c);
    DbgInc(L"DiskDone");
    if (!NT_SUCCESS(irp->IoStatus.Status)) return STATUS_SUCCESS;
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    if (sp->Parameters.DeviceIoControl.IoControlCode != IOCTL_STORAGE_QUERY_PROPERTY) return STATUS_SUCCESS;

    PSTORAGE_PROPERTY_QUERY q = (PSTORAGE_PROPERTY_QUERY)irp->AssociatedIrp.SystemBuffer;
    if (!q || q->PropertyId != StorageDeviceProperty || q->QueryType != PropertyStandardQuery) return STATUS_SUCCESS;

    PSTORAGE_DEVICE_DESCRIPTOR dd = (PSTORAGE_DEVICE_DESCRIPTOR)irp->AssociatedIrp.SystemBuffer;
    ULONG out = sp->Parameters.DeviceIoControl.OutputBufferLength;
    if (dd->SerialNumberOffset && dd->SerialNumberOffset < out)
        CopyA((PCHAR)dd + dd->SerialNumberOffset, out - dd->SerialNumberOffset, g_Cfg.DiskSerial, 20);
    return STATUS_SUCCESS;
}

static NTSTATUS HookDisk(PDEVICE_OBJECT dev, PIRP irp)
{
    if (IoGetCurrentIrpStackLocation(irp)->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        if (irp->CurrentLocation > 1) IoCopyCurrentIrpStackLocationToNext(irp);
        IoSetCompletionRoutine(irp, DiskDone, NULL, TRUE, TRUE, TRUE);
    }
    return g_OrigDisk(dev, irp);
}

static NTSTATUS VolDone(PDEVICE_OBJECT dev, PIRP irp, PVOID c)
{
    UNREFERENCED_PARAMETER(dev); UNREFERENCED_PARAMETER(c);
    DbgInc(L"VolDone");
    if (NT_SUCCESS(irp->IoStatus.Status)) {
        PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
        PVOID vb = irp->UserBuffer ? irp->UserBuffer : irp->AssociatedIrp.SystemBuffer;
        if (vb && sp->Parameters.QueryVolume.Length >= 12) {
            PFILE_FS_VOLUME_INFORMATION v = (PFILE_FS_VOLUME_INFORMATION)vb;
            v->VolumeSerialNumber = g_Cfg.VolumeSerial;
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS HookVol(PDEVICE_OBJECT dev, PIRP irp)
{
    if (irp->CurrentLocation > 1) IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, VolDone, NULL, TRUE, TRUE, TRUE);
    return g_OrigVol(dev, irp);
}

static NTSTATUS HookNdi(HANDLE h, HANDLE ev, PIO_APC_ROUTINE a, PVOID ac,
                        PIO_STATUS_BLOCK io, ULONG code, PVOID in, ULONG il,
                        PVOID out, ULONG ol)
{
    NTSTATUS st = ((PFN_NDICF)g_NdiCf)(h, ev, a, ac, io, code, in, il, out, ol);
    if (NT_SUCCESS(st) && code == IOCTL_NDIS_QUERY_GLOBAL_STATS && in && il >= 4 && out && ol >= 6) {
        ULONG oid = *(PULONG)in;
        if (oid == OID_802_3_CURRENT_ADDRESS || oid == OID_802_3_PERMANENT_ADDRESS)
            RtlCopyMemory(out, g_Cfg.Mac, 6);
    }
    return st;
}

static volatile LONG g_DbgBusy;

static void DbgSet(PCWSTR name, ULONG v)
{
    UNICODE_STRING u, vn;
    OBJECT_ATTRIBUTES oa;
    HANDLE h;

    RtlInitUnicodeString(&u, BK_KEY);
    InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateKey(&h, KEY_ALL_ACCESS, &oa, 0, NULL, 0, NULL))) return;
    RtlInitUnicodeString(&vn, name);
    ZwSetValueKey(h, &vn, 0, REG_DWORD, &v, sizeof(v));
    ZwClose(h);
}

static void DbgInc(PCWSTR name)
{
    UNICODE_STRING u, vn;
    OBJECT_ATTRIBUTES oa;
    HANDLE h;
    ULONG v = 0, sz = 0;
    UCHAR tmp[80];
    PKEY_VALUE_PARTIAL_INFORMATION kv = (PKEY_VALUE_PARTIAL_INFORMATION)tmp;

    if (InterlockedExchange(&g_DbgBusy, 1)) return;

    RtlInitUnicodeString(&u, BK_KEY);
    InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(ZwCreateKey(&h, KEY_ALL_ACCESS, &oa, 0, NULL, 0, NULL))) {
        RtlInitUnicodeString(&vn, name);
        if (NT_SUCCESS(ZwQueryValueKey(h, &vn, KeyValuePartialInformation, kv, sizeof(tmp), &sz))
            && kv->Type == REG_DWORD && kv->DataLength >= 4)
            v = *(PULONG)kv->Data;
        v++;
        ZwSetValueKey(h, &vn, 0, REG_DWORD, &v, sizeof(v));
        ZwClose(h);
    }

    InterlockedExchange(&g_DbgBusy, 0);
}
static void SmbSet(PUCHAR hdr, PUCHAR end, ULONG off, const CHAR* val)
{
    if (hdr + off >= end) return;
    ULONG nl = VnStrLenA((CHAR*)val);
    if (!nl) return;
    PUCHAR base = hdr + 4 + hdr[1];
    if (base >= end) return;

    UCHAR idx = hdr[off], n = 1, tidx = 0, bidx = 0;
    PUCHAR p = base, tgt = NULL, best = NULL;
    ULONG tlen = 0, blen = 0;

    while (p < end && *p) {
        ULONG ol = VnStrLenA((CHAR*)p);
        if (n == idx) { tgt = p; tlen = ol; tidx = n; }
        if (ol > blen) { best = p; blen = ol; bidx = n; }
        p += ol + 1;
        n++;
    }
    if ((!tgt || tlen < nl) && best) { tgt = best; tlen = blen; tidx = bidx; }
    if (!tgt || tlen < nl) return;

    hdr[off] = tidx;
    RtlCopyMemory(tgt, val, nl);
    for (ULONG i = nl; i < tlen; i++) tgt[i] = ' ';
    tgt[tlen] = 0;
}

static void PatchSmbios(PSFTI fi, ULONG len)
{
    if (!fi || len < 28) return;

    ULONG avail = fi->TableBufferLength;
    if (!avail || avail > len - 16) avail = len - 16;
    if (avail < 12) return;

    PUCHAR raw = fi->TableBuffer;
    if (!raw) return;
    DbgInc(L"SmbCall");
    DbgSet(L"SmbAvail", avail);
    DbgSet(L"SmbSig", *(PULONG)raw);

    ULONG tl = *(PULONG)(raw + 4);
    if (tl && tl + 8 < avail) avail = tl + 8;

    PUCHAR p = raw + 8, end = raw + avail;

    while (p + 4 < end) {
        UCHAR t = p[0];
        UCHAR sl = p[1];
        PUCHAR nx = p + 4 + sl;
        if (nx >= end) break;

        if (t == 1 && sl >= 0x19) {
            RtlCopyMemory(p + 8, g_Cfg.Uuid, 16); DbgInc(L"UuidHit"); DbgSet(L"UuidB0", *(PULONG)g_Cfg.Uuid);
        } else if (t == 2 && sl >= 8) {
            SmbSet(p, end, 5, g_Cfg.SysProduct);
            SmbSet(p, end, 7, g_Cfg.BoardSerial);
        } else if (t == 0 && sl >= 8) {
            SmbSet(p, end, 7, g_Cfg.BiosSerial);
        }

        while (nx + 1 < end && !(nx[0] == 0 && nx[1] == 0)) nx++;
        p = nx + 2;
    }
}
static NTSTATUS HookNqsi(SYSTEM_INFORMATION_CLASS c, PVOID buf, ULONG len, PULONG ret)
{
    DbgInc(L"NqsiAll");
    NTSTATUS st = ((PFN_NQSI)g_Nqsi)(c, buf, len, ret);

    if (c != SystemFirmwareTableInformation) return st;
    DbgInc(L"NqsiC76");
    if (!NT_SUCCESS(st) || !buf) return st;

    __try {
        PSFTI fi = (PSFTI)buf;
        DbgSet(L"NqsiSig", fi->ProviderSignature);
        DbgSet(L"NqsiAct", fi->Action);
        DbgSet(L"NqsiLen", fi->TableBufferLength);
        if (fi->ProviderSignature == 'RSMB' && fi->Action <= 2 && fi->TableBufferLength) {
            DbgInc(L"NqsiPath");
            PatchSmbios(fi, len);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { DbgInc(L"NqsiExc"); }

    return st;
}
static NTSTATUS RegSz(PCWSTR path, PCWSTR val, PCWSTR data)
{
    return RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, path, val, REG_SZ,
                                 (PVOID)data, ((ULONG)VnStrLenW(data) + 1) * sizeof(WCHAR));
}

static NTSTATUS RegRead(PCWSTR path, PCWSTR val, PWSTR out, ULONG cch)
{
    UNREFERENCED_PARAMETER(cch);
    RTL_QUERY_REGISTRY_TABLE tab[2] = {0};
    tab[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    tab[0].Name = (PWSTR)val;
    tab[0].EntryContext = (PVOID)out;
    tab[0].DefaultType = REG_SZ;
    tab[0].DefaultData = (PVOID)L"";
    tab[0].DefaultLength = 0;
    return RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, path, tab, NULL, NULL);
}

static void GuidApply()
{
    WCHAR cur[64] = {0};
    if (NT_SUCCESS(RegRead(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography",
                           L"MachineGuid", cur, 64)) && cur[0])
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
    int i;
    for (i = 0; i < 24 && g_Cfg.BoardSerial[i]; i++) w[i] = (WCHAR)g_Cfg.BoardSerial[i];
    RegSz(BIOS_KEY, L"BaseBoardSerialNumber", w);
    RtlZeroMemory(w, sizeof(w));
    for (i = 0; i < 24 && g_Cfg.SysProduct[i]; i++) w[i] = (WCHAR)g_Cfg.SysProduct[i];
    RegSz(BIOS_KEY, L"SystemProductName", w);
    RegSz(BIOS_KEY, L"BaseBoardProduct", w);
    RtlZeroMemory(w, sizeof(w));
    for (i = 0; i < 24 && g_Cfg.BiosSerial[i]; i++) w[i] = (WCHAR)g_Cfg.BiosSerial[i];
    RegSz(BIOS_KEY, L"BIOSVersion", w);
}

static NTSTATUS RegCopyVals(HANDLE src, HANDLE dst)
{
    ULONG sz = 0;
    ZwEnumerateValueKey(src, 0, KeyValueFullInformation, NULL, 0, &sz);
    if (!sz) return STATUS_SUCCESS;
    PKEY_VALUE_FULL_INFORMATION kv = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, sz, 'vpyR');
    if (!kv) return STATUS_INSUFFICIENT_RESOURCES;
    for (ULONG i = 0;; i++) {
        if (!NT_SUCCESS(ZwEnumerateValueKey(src, i, KeyValueFullInformation, kv, sz, &sz))) break;
        UNICODE_STRING vn;
        vn.Buffer = kv->Name;
        vn.Length = (USHORT)kv->NameLength;
        vn.MaximumLength = (USHORT)kv->NameLength;
        ZwSetValueKey(dst, &vn, 0, kv->Type, (PUCHAR)kv + kv->DataOffset, kv->DataLength);
    }
    ExFreePoolWithTag(kv, 'vpyR');
    return STATUS_SUCCESS;
}

static HANDLE OpenAbs(PCWSTR path, ACCESS_MASK acc, HANDLE parent)
{
    UNICODE_STRING u;
    RtlInitUnicodeString(&u, path);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, parent, NULL);
    HANDLE h = NULL;
    if (!NT_SUCCESS(ZwOpenKey(&h, acc, &oa))) return NULL;
    return h;
}

static HANDLE CreateAbs(PCWSTR path, HANDLE parent)
{
    UNICODE_STRING u;
    RtlInitUnicodeString(&u, path);
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
        if (ph2) {
            RegCopyVals(ph, ph2);
            ZwClose(ph2);
        }
        ZwDeleteKey(ph);
        ZwClose(ph);
    }
    ZwClose(th);
    ZwDeleteKey(sh);
    ZwClose(sh);
    return STATUS_SUCCESS;
}

static BOOLEAN PrefEq(PCWSTR a, ULONG alen, PCWSTR b, ULONG blen)
{
    if (!alen || blen < alen) return FALSE;
    for (ULONG i = 0; i < alen; i++)
        if (RtlUpcaseUnicodeChar(a[i]) != RtlUpcaseUnicodeChar(b[i])) return FALSE;
    return TRUE;
}

static NTSTATUS GpuApply()
{
    HANDLE root = OpenAbs(GPU_CLASS_KEY, KEY_READ);
    if (!root) return STATUS_UNSUCCESSFUL;
    HANDLE pci = OpenAbs(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\PCI", KEY_READ);
    if (!pci) { ZwClose(root); return STATUS_UNSUCCESSFUL; }

    ULONG n = 0, i = 0, saved = 0;
    WCHAR path[420], dev[460], src[520], dst[540], cnt[8];
    while (NT_SUCCESS(ZwEnumerateKey(root, i++, KeyBasicInformation, (PVOID)g_EnumBuf, 512, &n))) {
        PKEY_BASIC_INFORMATION kb = (PKEY_BASIC_INFORMATION)g_EnumBuf;
        WCHAR md[300] = {0};
        PWSTR mdp;
        ULONG ml;

        CopyW(path, 420, GPU_CLASS_KEY, 420); Append(path, 420, L"\\"); AppendN(path, 420, kb->Name, kb->NameLength / 2);
        if (!NT_SUCCESS(RegRead(path, L"MatchingDeviceId", md, 300)) || !md[0]) continue;
        DbgInc(L"GpuMd");

        ml = (ULONG)VnStrLenW(md);
        mdp = md;
        if (ml > 4 && (md[0] == L'p' || md[0] == L'P') && md[3] == L'\\') { mdp = md + 4; ml -= 4; }

        ULONG e = 0, m2 = 0;
        while (NT_SUCCESS(ZwEnumerateKey(pci, e++, KeyBasicInformation, (PVOID)g_EnumBuf2, 512, &m2))) {
            PKEY_BASIC_INFORMATION eb = (PKEY_BASIC_INFORMATION)g_EnumBuf2;
            if (!PrefEq(mdp, ml, eb->Name, eb->NameLength / 2)) continue;

            CopyW(dev, 460, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\", 460);
            AppendN(dev, 460, eb->Name, eb->NameLength / 2);

            DbgInc(L"GpuMatch");
            HANDLE dh = OpenAbs(dev, KEY_READ);
            if (!dh) continue;

            ULONG m = 0, k = 0;
            while (NT_SUCCESS(ZwEnumerateKey(dh, k++, KeyBasicInformation, (PVOID)g_EnumBuf2, 512, &m))) {
                PKEY_BASIC_INFORMATION ib = (PKEY_BASIC_INFORMATION)g_EnumBuf2;
                CopyW(src, 520, dev, 520); Append(src, 520, L"\\"); AppendN(src, 520, ib->Name, ib->NameLength / 2);
                CopyW(dst, 540, src, 540); Append(dst, 540, L"-SPOOF");
                if (NT_SUCCESS(GpuMove(src, dst))) {
                    NumW(cnt, 8, saved++);
                    RegSz(BK_KEY, cnt, src);
                }
            }
            ZwClose(dh);
            break;
        }
    }
    ZwClose(pci);
    ZwClose(root);
    DbgDw(L"GpuSaved", saved);
    g_HookGpu = TRUE;
    return STATUS_SUCCESS;
}
static void GpuRevert()
{
    WCHAR src[760], back[720], cnt[8];
    for (ULONG i = 0; i < 32; i++) {
        NumW(cnt, 8, i);
        WCHAR val[760] = {0};
        if (!NT_SUCCESS(RegRead(BK_KEY, cnt, val, 760)) || !val[0]) continue;
        CopyW(src, 760, val, 760);
        CopyW(back, 720, src, 720); Append(back, 720, L"-SPOOF");
        GpuMove(back, src);
        RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, BK_KEY, cnt);
    }
    g_HookGpu = FALSE;
}


static void MacHex(PWSTR out)
{
    const WCHAR* hx = L"0123456789ABCDEF";
    for (int i = 0; i < 6; i++) { out[i * 2] = hx[g_Cfg.Mac[i] >> 4]; out[i * 2 + 1] = hx[g_Cfg.Mac[i] & 15]; }
    out[12] = 0;
}

static void MacRegApply()
{
    WCHAR hex[16], path[420], cnt[8];
    ULONG n = 0, i = 0, saved = 0;

    MacHex(hex);
    HANDLE root = OpenAbs(NET_CLASS, KEY_ENUMERATE_SUB_KEYS, NULL);
    if (!root) return;

    while (NT_SUCCESS(ZwEnumerateKey(root, i++, KeyBasicInformation, (PVOID)g_EnumBuf, 512, &n))) {
        PKEY_BASIC_INFORMATION kb = (PKEY_BASIC_INFORMATION)g_EnumBuf;
        WCHAR id[64] = {0};
        CopyW(path, 420, NET_CLASS, 420); Append(path, 420, L"\\"); AppendN(path, 420, kb->Name, kb->NameLength / 2);
        if (!NT_SUCCESS(RegRead(path, L"NetCfgInstanceId", id, 64)) || !id[0]) continue;
        RegSz(path, L"NetworkAddress", hex);
        NumW(cnt, 8, saved++);
        RegSz(BK_KEY, cnt, path);
    }
    ZwClose(root);
}

static void MacRegRevert()
{
    WCHAR path[420], cnt[8];
    for (ULONG i = 0; i < 64; i++) {
        NumW(cnt, 8, i);
        WCHAR v[420] = {0};
        if (!NT_SUCCESS(RegRead(BK_KEY, cnt, v, 420)) || !v[0]) continue;
        CopyW(path, 420, v, 420);
        RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, path, L"NetworkAddress");
        RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, BK_KEY, cnt);
    }
}
static NTSTATUS DoApply(PSPOOF_CFG c)
{
    if (g_Applied) return STATUS_ALREADY_REGISTERED;
    RtlCopyMemory(&g_Cfg, c, sizeof(SPOOF_CFG));

    if (c->Flags & SPOOF_DISK) {
        g_DrvDisk = DrvOfVolume(L"\\Device\\Harddisk0\\DR0");
        { NTSTATUS hs = HookDrv(g_DrvDisk, IRP_MJ_DEVICE_CONTROL, (PVOID)HookDisk, (PVOID*)&g_OrigDisk);
          DbgDw(L"DiskDrv", g_DrvDisk ? 1u : 0u); DbgDw(L"DiskSt", (ULONG)hs);
          if (NT_SUCCESS(hs)) g_HookDisk = TRUE; }
    }

    if (c->Flags & SPOOF_VOLUME) {
        for (int vi = 1; vi <= 4 && !g_DrvVol; vi++) {
            WCHAR vn[40];
            CopyW(vn, 40, L"\\Device\\HarddiskVolume", 40); { WCHAR nb[8]; NumW(nb, 8, (ULONG)vi); Append(vn, 40, nb); }
            g_DrvVol = DrvOfVolume(vn);
        }
        { NTSTATUS hs = HookDrv(g_DrvVol, IRP_MJ_QUERY_VOLUME_INFORMATION, (PVOID)HookVol, (PVOID*)&g_OrigVol);
          DbgDw(L"VolDrv", g_DrvVol ? 1u : 0u); DbgDw(L"VolSt", (ULONG)hs);
          if (NT_SUCCESS(hs)) g_HookVol = TRUE; }
    }

    if (c->Flags & SPOOF_MAC) {
        UNICODE_STRING n;
        RtlInitUnicodeString(&n, L"NtDeviceIoControlFile");
        g_NdiCf = MmGetSystemRoutineAddress(&n);
        if (g_NdiCf && NT_SUCCESS(DetourInstall(&g_DtNdi, g_NdiCf, (PVOID)HookNdi))) { g_HookMac = TRUE; g_NdiCf = g_DtNdi.Tramp; }
        MacRegApply();
    }
    if (c->Flags & SPOOF_SMBIOS) {
        UNICODE_STRING n;
        RtlInitUnicodeString(&n, L"NtQuerySystemInformation");
        g_Nqsi = MmGetSystemRoutineAddress(&n);
        { NTSTATUS ds = g_Nqsi ? DetourInstall(&g_DtNqsi, g_Nqsi, (PVOID)HookNqsi) : STATUS_NOT_FOUND;
            DbgDw(L"SmbStatus", (ULONG)ds); DbgDw(L"SmbStep", g_Step);
            if (g_DtNqsi.Target) { PULONG q = (PULONG)g_DtNqsi.Target; DbgDw(L"SmbT0", q[0]); DbgDw(L"SmbT1", q[1]); DbgDw(L"SmbT2", q[2]); DbgDw(L"SmbT3", q[3]); }
            if (NT_SUCCESS(ds)) { g_HookSmb = TRUE; g_Nqsi = g_DtNqsi.Tramp; } }
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
    if (g_Cfg.Flags & SPOOF_MAC) MacRegRevert();
    if (g_HookVol) { HookDrv(g_DrvVol, IRP_MJ_QUERY_VOLUME_INFORMATION, (PVOID)g_OrigVol, (PVOID*)&g_OrigVol); g_HookVol = FALSE; }
    if (g_HookDisk) { HookDrv(g_DrvDisk, IRP_MJ_DEVICE_CONTROL, (PVOID)g_OrigDisk, (PVOID*)&g_OrigDisk); g_HookDisk = FALSE; }
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

    if (sp->MajorFunction == IRP_MJ_CREATE || sp->MajorFunction == IRP_MJ_CLOSE) {
        st = STATUS_SUCCESS;
    } else if (sp->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;
        if (code == IOCTL_APPLY && sp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(SPOOF_CFG)) {
            st = DoApply((PSPOOF_CFG)irp->AssociatedIrp.SystemBuffer);
        } else if (code == IOCTL_REVERT) {
            st = DoRevert();
        } else if (code == IOCTL_STATE && sp->Parameters.DeviceIoControl.OutputBufferLength >= 1) {
            *(PUCHAR)irp->AssociatedIrp.SystemBuffer = g_Applied ? 1 : 0;
            out = 1;
            st = STATUS_SUCCESS;
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
    UNICODE_STRING s;
    RtlInitUnicodeString(&s, SYM_NAME);
    IoDeleteSymbolicLink(&s);
    IoDeleteDevice(d->DeviceObject);
}

static BOOLEAN RegisterSeh(PVOID anchor)
{
    typedef BOOLEAN (*PFN_ADDFT)(PVOID, ULONG, ULONG64);
    UNICODE_STRING un;
    PFN_ADDFT pAdd;
    ULONG64 p = (ULONG64)anchor & ~0xFFFULL;
    LONG  lfanew;
    ULONG rva, size;
    int   i;

    for (i = 0; i < 1024; i++, p -= 0x1000) {
        if (*(PUSHORT)p == 0x5A4D) break;
    }
    if (i >= 1024) return FALSE;

    lfanew = *(PLONG)(p + 0x3C);
    if (lfanew <= 0 || lfanew > 0x1000) return FALSE;
    if (*(PULONG)(p + lfanew) != 0x00004550) return FALSE;

    rva  = *(PULONG)(p + lfanew + 24 + 0x88);
    size = *(PULONG)(p + lfanew + 24 + 0x8C);
    if (!rva || size < 12) return FALSE;

    RtlInitUnicodeString(&un, L"RtlAddFunctionTable");
    pAdd = (PFN_ADDFT)MmGetSystemRoutineAddress(&un);
    if (!pAdd) return FALSE;

    return pAdd((PVOID)(p + rva), size / 12, p);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNREFERENCED_PARAMETER(reg);
    if (!drv) return STATUS_UNSUCCESSFUL;
    RegisterSeh((PVOID)DriverEntry);
    UNICODE_STRING n, s;
    RtlInitUnicodeString(&n, DEV_NAME);
    RtlInitUnicodeString(&s, SYM_NAME);

    PDEVICE_OBJECT dev = NULL;
    NTSTATUS st = IoCreateDevice(drv, 0, &n, FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;
    IoCreateSymbolicLink(&s, &n);

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) drv->MajorFunction[i] = Dispatch;
    drv->DriverUnload = Unload;
    dev->Flags |= DO_BUFFERED_IO;
    dev->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

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
    if (g_TrampNext >= 4) return STATUS_INSUFFICIENT_RESOURCES;

    for (int hop = 0; hop < 4; hop++) {
        PUCHAR p = (PUCHAR)t;
        if (p[0] == 0xE9) { t = p + 5 + *(LONG*)(p + 1); if (!IsKernelPtr(t)) return STATUS_UNSUCCESSFUL; continue; }
        if (p[0] == 0xEB) { t = p + 2 + (LONG)(*(signed char*)(p + 1)); if (!IsKernelPtr(t)) return STATUS_UNSUCCESSFUL; continue; }
        break;
    }

    while (len < 14) {
        if (!hde64_disasm((PUCHAR)t + len, &hs) || hs.len == 0 || hs.len > 15) return STATUS_UNSUCCESSFUL;
        len += hs.len;
        nins++;
        if (nins > 8 || len > 24) return STATUS_UNSUCCESSFUL;
    }

    d->Target   = t;
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

    dst[out] = 0xFF;
    dst[out + 1] = 0x25;
    *(LONG*)(dst + out + 2) = 0;
    *(PVOID*)(dst + out + 6) = (PUCHAR)t + len;
    d->TrampLen = out + 14;

    {
        ULONG vl = 0, vc = 0, k;
        BOOLEAN bad = FALSE;
        for (k = 0; k < nins; k++) {
            hde64s vs;
            if (!hde64_disasm(dst + vl, &vs) || vs.len == 0) { bad = TRUE; break; }
            vl += vs.len;
            vc++;
        }
        if (bad || vc != nins || vl != out) return STATUS_UNSUCCESSFUL;
    }

    WpOff();
    {
        PUCHAR p = (PUCHAR)t;
        p[0] = 0x48; p[1] = 0xB8;
        *(PVOID*)(p + 2) = h;
        p[10] = 0xFF; p[11] = 0xE0;
        for (ULONG k = 12; k < len; k++) p[k] = 0x90;
        KeMemoryBarrier();
    }
    WpOn();

    if (((PUCHAR)t)[0] != 0x48 || ((PUCHAR)t)[10] != 0xFF) {
        WpOff();
        RtlCopyMemory((PUCHAR)t, d->Stolen, len);
        KeMemoryBarrier();
        WpOn();
        return STATUS_UNSUCCESSFUL;
    }

    d->Active = TRUE;
    return STATUS_SUCCESS;
}
static void DetourRemove(DETOUR* d)
{
    if (!d || !d->Active) return;
    WpOff();
    RtlCopyMemory(d->Target, d->Stolen, d->Len);
    KeMemoryBarrier();
    WpOn();
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
    while (dev->AttachedDevice) dev = dev->AttachedDevice;
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
        CopyA((PCHAR)dd + dd->SerialNumberOffset, out - dd->SerialNumberOffset, g_Cfg.DiskSerial, 20);
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
        PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
        if (sp->Parameters.DeviceIoControl.OutputBufferLength >= 12) {
            PFILE_FS_VOLUME_INFORMATION v = (PFILE_FS_VOLUME_INFORMATION)irp->AssociatedIrp.SystemBuffer;
            if (v) v->VolumeSerialNumber = g_Cfg.VolumeSerial;
        }
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

static void SmbStr(PUCHAR hdr, PUCHAR end, UCHAR idx, const CHAR* val)
{
    if (!idx) return;
    PUCHAR p = hdr + 4 + hdr[1];
    for (UCHAR i = 1; i <= idx; i++) {
        if (p >= end) return;
        if (i == idx) {
            CopyA((CHAR*)p, VnStrLenA((CHAR*)p) + 1, val, VnStrLenA((CHAR*)p));
            return;
        }
        p += VnStrLenA((CHAR*)p) + 1;
    }
}

static void PatchSmbios(PSFTI fi, ULONG len)
{
    PUCHAR raw, p, end;
    ULONG  avail;

    if (!fi || len < 28) return;
    if (fi->TableBufferLength < 12) return;

    avail = len - 16;
    if (fi->TableBufferLength < avail) avail = fi->TableBufferLength;
    if (avail < 12) return;

    raw = fi->TableBuffer;
    p   = raw + 8;
    end = raw + avail;

    while (p + 4 < end) {
        UCHAR t = p[0];
        UCHAR sl = p[1];
        PUCHAR nx = p + 4 + sl;
        if (nx >= end) break;
        if (t == 1 && sl >= 0x19) {
            RtlCopyMemory(p + 8, g_Cfg.Uuid, 16);
            SmbStr(p, end, p[5], g_Cfg.SysProduct);
        } else if (t == 2 && sl >= 8) {
            SmbStr(p, end, p[7], g_Cfg.BoardSerial);
        } else if (t == 0 && sl >= 8) {
            SmbStr(p, end, p[7], g_Cfg.BiosSerial);
        }
        while (nx + 1 < end && !(nx[0] == 0 && nx[1] == 0)) nx++;
        p = nx + 2;
    }
}
static NTSTATUS HookNqsi(SYSTEM_INFORMATION_CLASS c, PVOID buf, ULONG len, PULONG ret)
{
    NTSTATUS st = ((PFN_NQSI)g_Nqsi)(c, buf, len, ret);

    if (!NT_SUCCESS(st) || c != SystemFirmwareTableInformation || !buf) return st;

    __try {
        PSFTI fi = (PSFTI)buf;
        if (fi->ProviderSignature == 'RSMB' && fi->Action == 0 && fi->TableBufferLength)
            PatchSmbios(fi, len);
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

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

static NTSTATUS GpuApply()
{
    WCHAR base[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\PCI";
    HANDLE root = OpenAbs(base, KEY_ENUMERATE_SUB_KEYS, NULL);
    if (!root) return STATUS_UNSUCCESSFUL;

    ULONG n = 0, i = 0, saved = 0;
    WCHAR tmp[700], dst[720], cnt[8];
    while (NT_SUCCESS(ZwEnumerateKey(root, i++, KeyBasicInformation, (PVOID)g_EnumBuf, 512, &n))) {
        PKEY_BASIC_INFORMATION kb = (PKEY_BASIC_INFORMATION)g_EnumBuf;
        if (kb->NameLength < 8) continue;
        if (kb->Name[0] != L'V' || kb->Name[1] != L'E' ||
            kb->Name[2] != L'N' || kb->Name[3] != L'_') continue;

        UNICODE_STRING kn;
        kn.Buffer = kb->Name;
        kn.Length = (USHORT)kb->NameLength;
        kn.MaximumLength = (USHORT)kb->NameLength;
        Append(tmp, 700, base); Append(tmp, 700, L"\\"); AppendN(tmp, 700, kn.Buffer, kn.Length / 2);
        WCHAR cls[64] = {0};
        if (!NT_SUCCESS(RegRead(tmp, L"ClassGUID", cls, 64))) continue;
        {
            UNICODE_STRING ua, ub;
            RtlInitUnicodeString(&ua, cls);
            RtlInitUnicodeString(&ub, GPU_CLASS);
            if (!RtlEqualUnicodeString(&ua, &ub, TRUE)) continue;
        }

        HANDLE dh = OpenAbs(tmp, KEY_ENUMERATE_SUB_KEYS, NULL);
        if (!dh) continue;

        ULONG m = 0, k = 0;
        while (NT_SUCCESS(ZwEnumerateKey(dh, k++, KeyBasicInformation, (PVOID)g_EnumBuf2, 512, &m))) {
            PKEY_BASIC_INFORMATION ib = (PKEY_BASIC_INFORMATION)g_EnumBuf2;
            WCHAR src[760];
            UNICODE_STRING in2;
            in2.Buffer = ib->Name;
            in2.Length = (USHORT)ib->NameLength;
            in2.MaximumLength = (USHORT)ib->NameLength;
            CopyW(src, 760, tmp, 760); Append(src, 760, L"\\"); AppendN(src, 760, in2.Buffer, in2.Length / 2);
            CopyW(dst, 720, src, 720); Append(dst, 720, L"-SPOOF");
            if (NT_SUCCESS(GpuMove(src, dst))) {
                NumW(cnt, 8, saved++);
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

static NTSTATUS DoApply(PSPOOF_CFG c)
{
    if (g_Applied) return STATUS_ALREADY_REGISTERED;
    RtlCopyMemory(&g_Cfg, c, sizeof(SPOOF_CFG));

    if (c->Flags & SPOOF_DISK) {
        g_DrvDisk = DrvOfVolume(L"\\Device\\Harddisk0\\DR0");
        if (NT_SUCCESS(HookDrv(g_DrvDisk, IRP_MJ_DEVICE_CONTROL, (PVOID)HookDisk, (PVOID*)&g_OrigDisk)))
            g_HookDisk = TRUE;
    }

    if (c->Flags & SPOOF_VOLUME) {
        for (int vi = 1; vi <= 4 && !g_DrvVol; vi++) {
            WCHAR vn[40];
            CopyW(vn, 40, L"\\Device\\HarddiskVolume", 40); { WCHAR nb[8]; NumW(nb, 8, (ULONG)vi); Append(vn, 40, nb); }
            g_DrvVol = DrvOfVolume(vn);
        }
        if (NT_SUCCESS(HookDrv(g_DrvVol, IRP_MJ_QUERY_VOLUME_INFORMATION, (PVOID)HookVol, (PVOID*)&g_OrigVol)))
            g_HookVol = TRUE;
    }

    if (c->Flags & SPOOF_MAC) {
        UNICODE_STRING n;
        RtlInitUnicodeString(&n, L"NtDeviceIoControlFile");
        g_NdiCf = MmGetSystemRoutineAddress(&n);
        if (g_NdiCf && NT_SUCCESS(DetourInstall(&g_DtNdi, g_NdiCf, (PVOID)HookNdi))) { g_HookMac = TRUE; g_NdiCf = g_DtNdi.Tramp; }
    }
    if (c->Flags & SPOOF_SMBIOS) {
        UNICODE_STRING n;
        RtlInitUnicodeString(&n, L"NtQuerySystemInformation");
        g_Nqsi = MmGetSystemRoutineAddress(&n);
        if (g_Nqsi && NT_SUCCESS(DetourInstall(&g_DtNqsi, g_Nqsi, (PVOID)HookNqsi))) { g_HookSmb = TRUE; g_Nqsi = g_DtNqsi.Tramp; }
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

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNREFERENCED_PARAMETER(reg);
    if (!drv) return STATUS_UNSUCCESSFUL;
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

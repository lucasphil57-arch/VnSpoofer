$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$work = Join-Path $env:TEMP 'vnsmoke'
New-Item -ItemType Directory -Force $work | Out-Null
Copy-Item (Join-Path $root 'driver\VnSpoofer.sys') (Join-Path $work 'VnSpoofer.sys') -Force
Copy-Item (Join-Path $root 'app\res\kdu.exe') (Join-Path $work 'kdu.exe') -Force
Copy-Item (Join-Path $root 'app\res\drv64.dll') (Join-Path $work 'drv64.dll') -Force

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class D {
  [DllImport("kernel32", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
  [DllImport("kernel32", SetLastError=true)]
  public static extern bool DeviceIoControl(IntPtr h, uint c, byte[] i, uint il, byte[] o, uint ol, out uint br, IntPtr ov);
  [DllImport("kernel32")] public static extern bool CloseHandle(IntPtr h);
}
"@

function Open-Dev {
  $h = [D]::CreateFileW('\\.\VnSpoofer', [uint32]3221225472, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
  if ($h -eq [IntPtr](-1)) { return $null }
  return $h
}

$ids = @()
& (Join-Path $work 'kdu.exe') -listcsv (Join-Path $work 'p.csv') | Out-Null
if (Test-Path (Join-Path $work 'p.csv')) {
  foreach ($l in Get-Content (Join-Path $work 'p.csv')) {
    $t = ($l -split '[,;]')[0].Trim().Trim('"')
    if ($t -match '^\d{1,2}$' -and $ids -notcontains $t) { $ids += $t }
  }
}
if ($ids.Count -eq 0) { $ids = 0..70 | ForEach-Object { "$_" } }
$max = if ($env:SMOKE_MAX) { [int]$env:SMOKE_MAX } else { 8 }
if ($ids.Count -gt $max) { $ids = $ids[0..($max-1)] }

$h = $null
foreach ($id in $ids) {
  Write-Host "--- provider $id"
  & (Join-Path $work 'kdu.exe') -prv $id -map (Join-Path $work 'VnSpoofer.sys') 2>&1 | Select-Object -Last 6 | ForEach-Object { Write-Host "    $_" }
  $h = Open-Dev
  if ($h) { Write-Host "MAPPE via $id" -ForegroundColor Green; break }
}
if (-not $h) { throw 'mapping impossible' }

$buf = New-Object byte[] 166
[BitConverter]::GetBytes([uint32]$env:SMOKE_FLAGS).CopyTo($buf, 0)
$enc = [Text.Encoding]::ASCII
$enc.GetBytes('SMOKEDISK0000000000').CopyTo($buf, 4)
[BitConverter]::GetBytes([uint32]0x1234ABCD).CopyTo($buf, 28)
[byte[]](0x02,0x11,0x22,0x33,0x44,0x55).CopyTo($buf, 32)
[Guid]::Parse('11112222-3333-4444-8888-99990000aaaa').ToByteArray().CopyTo($buf, 38)
$enc.GetBytes('SMOKEBOARD000000').CopyTo($buf, 54)
$enc.GetBytes('SMOKEBIOS0000000').CopyTo($buf, 78)
$enc.GetBytes('SMOKEPROD0000000').CopyTo($buf, 102)
$enc.GetBytes('aaaa1111-2222-4333-8444-555566667777').CopyTo($buf, 126)

$br = 0
$ok = [D]::DeviceIoControl($h, 0x00222000, $buf, 166, $null, 0, [ref]$br, [IntPtr]::Zero)
Write-Host "IOCTL_APPLY : $ok"
if (-not $ok) { throw 'apply refuse' }

Write-Host '--- lecture retour'
Write-Host ("DISQUE : " + (Get-CimInstance Win32_DiskDrive | Select-Object -First 1 -ExpandProperty SerialNumber))
Write-Host ("UUID   : " + (Get-CimInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID))
Write-Host ("MAC    : " + ((Get-NetAdapter | Select-Object -First 1).MacAddress))
Write-Host ("GUID   : " + ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid))

$ok2 = [D]::DeviceIoControl($h, 0x00222004, $null, 0, $null, 0, [ref]$br, [IntPtr]::Zero)
Write-Host "IOCTL_REVERT : $ok2"
[D]::CloseHandle($h) | Out-Null
Write-Host 'SMOKE OK' -ForegroundColor Green

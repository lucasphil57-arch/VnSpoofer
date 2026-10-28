$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$work = Join-Path $here '.wdk'
New-Item -ItemType Directory -Force $work | Out-Null

function Fetch($id, $dir) {
    if (Test-Path $dir) { return }
    $zip = Join-Path $work "$id.zip"
    Invoke-WebRequest "https://www.nuget.org/api/v2/package/$id" -OutFile $zip
    Expand-Archive $zip -DestinationPath $dir -Force
}

Fetch 'Microsoft.Windows.WDK.x64' (Join-Path $work 'wdk')
Fetch 'Microsoft.Windows.SDK.CPP.x64' (Join-Path $work 'sdk')

$kh = Get-ChildItem (Join-Path $work 'wdk') -Recurse -Filter ntddk.h | Where-Object { $_.FullName -match '\\km\\' } | Select-Object -First 1
if (-not $kh) { throw 'ntddk.h introuvable (wdk nuget)' }
$ver = $kh.Directory.Parent.Name
$wRoot = $kh.Directory.Parent.Parent.Parent.FullName
$wInc = Join-Path $wRoot "Include\$ver"
$wLib = Join-Path $wRoot "Lib\$ver\km\x64"

$eh = Get-ChildItem (Join-Path $work 'sdk') -Recurse -Filter excpt.h | Select-Object -First 1
if (-not $eh) { throw 'excpt.h introuvable (sdk nuget)' }
$sVer = $eh.Directory.Parent.Name
$sRoot = $eh.Directory.Parent.Parent.Parent.FullName
$sInc = Join-Path $sRoot "Include\$sVer"
$sLib = Join-Path $sRoot "Lib\$sVer\km\x64"
Write-Host "WDK $ver / SDK $sVer"

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$cl = & $vswhere -latest -products * -find 'VC\Tools\MSVC\**\bin\Hostx64\x64\cl.exe' | Select-Object -First 1
if (-not $cl) { throw 'cl.exe introuvable' }
$link = Join-Path (Split-Path $cl) 'link.exe'
$msvc = Split-Path (Split-Path (Split-Path $cl))

$incDirs = @((Join-Path $msvc 'include'), (Join-Path $wInc 'km'), (Join-Path $wInc 'shared'),
             (Join-Path $sInc 'ucrt'), (Join-Path $sInc 'shared'), (Join-Path $sInc 'um')) |
           Where-Object { Test-Path $_ }

$objs = @()
foreach ($f in @('main.cpp', 'hde64.c')) {
    $o = Join-Path $work ([IO.Path]::GetFileNameWithoutExtension($f) + '.obj')
    $rsp = Join-Path $work ([IO.Path]::GetFileNameWithoutExtension($f) + '.rsp')
    $l = @('/nologo', '/c', '/kernel', '/GS-', '/Gs9999999', '/O2', '/Oi',
           '/D_AMD64_', '/DAMD64', '/D_WIN64', '/DNT', '/DPOOL_NX_OPTIN=0', '/D_CRT_SECURE_NO_WARNINGS')
    if ($f.EndsWith('.cpp')) { $l += '/std:c++17'; $l += '/TP' } else { $l += '/TC' }
    foreach ($d in $incDirs) { $l += "/I`"$d`"" }
    $l += "/Fo`"$o`""
    Set-Content $rsp $l -Encoding ASCII
    Write-Host "--- $f ---"; Get-Content $rsp | ForEach-Object { Write-Host "  $_" }
    & $cl "@$rsp" (Join-Path $here $f)
    if ($LASTEXITCODE -ne 0) { throw "echec compilation $f" }
    $objs += $o
}

$lrsp = Join-Path $work 'link.rsp'
$ll = @('/nologo', '/DRIVER', '/SUBSYSTEM:NATIVE', '/ENTRY:DriverEntry', '/MACHINE:X64', '/NODEFAULTLIB', '/RELEASE',
        "/OUT:`"$here\VnSpoofer.sys`"")
foreach ($d in @($wLib, $sLib, (Join-Path $msvc 'lib\x64'))) { if (Test-Path $d) { $ll += "/LIBPATH:`"$d`"" } }
$ll += $objs; $ll += @('ntoskrnl.lib', 'wdm.lib', 'hal.lib', 'BufferOverflowK.lib')
Set-Content $lrsp $ll -Encoding ASCII
& $link "@$lrsp"
if ($LASTEXITCODE -ne 0) { throw 'echec link' }
Write-Host "OK -> $here\VnSpoofer.sys"

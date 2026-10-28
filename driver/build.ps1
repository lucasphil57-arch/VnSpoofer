$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$work = Join-Path $here '.wdk'

if (-not (Test-Path (Join-Path $work 'pkg'))) {
    New-Item -ItemType Directory -Force $work | Out-Null
    $zip = Join-Path $work 'wdk.zip'
    Invoke-WebRequest 'https://www.nuget.org/api/v2/package/Microsoft.Windows.WDK.x64' -OutFile $zip
    Expand-Archive $zip -DestinationPath (Join-Path $work 'pkg') -Force
}

$inc = Get-ChildItem (Join-Path $work 'pkg') -Recurse -Filter ntddk.h |
       Where-Object { $_.FullName -match '\\km\\' } | Select-Object -First 1
if (-not $inc) { throw 'ntddk.h introuvable dans le paquet NuGet' }
$ver     = $inc.Directory.Parent.Name
$pkgRoot = $inc.Directory.Parent.Parent.Parent.FullName
$wdkInc  = Join-Path $pkgRoot "Include\$ver"
$wdkLib  = Join-Path $pkgRoot "Lib\$ver\km\x64"
Write-Host "WDK nuget $ver"

$sdkRoot = 'C:\Program Files (x86)\Windows Kits\10'
$sdkInc  = Join-Path $sdkRoot "Include\$ver"
if (-not (Test-Path (Join-Path $sdkInc 'um'))) {
    $sdkInc = (Get-ChildItem (Join-Path $sdkRoot 'Include') -Directory |
               Where-Object { Test-Path (Join-Path $_.FullName 'um') } |
               Sort-Object Name -Descending | Select-Object -First 1).FullName
}
Write-Host "SDK $sdkInc"
$sdkLib = Join-Path $sdkRoot "Lib\$ver\km\x64"

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$cl = & $vswhere -latest -products * -find 'VC\Tools\MSVC\**\bin\Hostx64\x64\cl.exe' | Select-Object -First 1
if (-not $cl) { throw 'cl.exe introuvable' }
$link = Join-Path (Split-Path $cl) 'link.exe'
$msvc = Split-Path (Split-Path (Split-Path $cl))
$msvcInc = Join-Path $msvc 'include'
$msvcLib = Join-Path $msvc 'lib\x64'

# /I et le chemin en DEUX arguments (les chemins contiennent des espaces)
$incArgs = @()
foreach ($d in @($msvcInc, (Join-Path $wdkInc 'km'), (Join-Path $wdkInc 'shared'),
                 (Join-Path $sdkInc 'shared'), (Join-Path $sdkInc 'ucrt'), (Join-Path $sdkInc 'um'))) {
    if (Test-Path $d) { $incArgs += '/I'; $incArgs += $d }
}
$defs = @('/D_AMD64_', '/DAMD64', '/D_WIN64', '/DNT', '/DPOOL_NX_OPTIN=0', '/D_CRT_SECURE_NO_WARNINGS')

$objs = @()
foreach ($f in @('main.cpp', 'hde64.c')) {
    $o = Join-Path $work ([IO.Path]::GetFileNameWithoutExtension($f) + '.obj')
    $std = if ($f.EndsWith('.cpp')) { @('/std:c++17', '/TP') } else { @('/TC') }
    Write-Host "cl $f"
    & $cl /nologo /c /kernel /GS- /Gs9999999 /O2 /Oi @defs @std @incArgs "/Fo$o" (Join-Path $here $f)
    if ($LASTEXITCODE -ne 0) { throw "echec compilation $f" }
    $objs += $o
}

$libArgs = @()
foreach ($d in @($wdkLib, $sdkLib, $msvcLib)) { if (Test-Path $d) { $libArgs += '/LIBPATH'; $libArgs += $d } }

& $link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /MACHINE:X64 /NODEFAULTLIB /RELEASE `
      "/OUT:$here\VnSpoofer.sys" @objs @libArgs ntoskrnl.lib wdm.lib hal.lib BufferOverflowK.lib
if ($LASTEXITCODE -ne 0) { throw 'echec link' }
Write-Host "OK -> $here\VnSpoofer.sys"

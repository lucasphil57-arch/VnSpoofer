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
if (-not $inc) {
    Get-ChildItem (Join-Path $work 'pkg') -Recurse -Filter *.h | Select-Object -First 20 -ExpandProperty FullName
    throw 'ntddk.h introuvable dans le paquet NuGet'
}
$ver     = $inc.Directory.Parent.Name
$pkgRoot = $inc.Directory.Parent.Parent.Parent.FullName
$wdkInc  = Join-Path $pkgRoot "Include\$ver"
$wdkLib  = Join-Path $pkgRoot "Lib\$ver\km\x64"
Write-Host "WDK nuget $ver"

$sdkRoot = 'C:\Program Files (x86)\Windows Kits\10'
$sdkInc  = Join-Path $sdkRoot "Include\$ver"
if (-not (Test-Path $sdkInc)) {
    $sdkInc = (Get-ChildItem (Join-Path $sdkRoot 'Include') -Directory | Sort-Object Name -Descending | Select-Object -First 1).FullName
}
$sdkLib = Join-Path $sdkRoot "Lib\$ver\km\x64"

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$cl = & $vswhere -latest -products * -find 'VC\Tools\MSVC\**\bin\Hostx64\x64\cl.exe' | Select-Object -First 1
if (-not $cl) { throw 'cl.exe introuvable' }
$link = Join-Path (Split-Path $cl) 'link.exe'
$msvc = Split-Path (Split-Path (Split-Path $cl))
$msvcInc = Join-Path $msvc 'include'

$incArgs = @("/I$msvcInc", "/I$(Join-Path $wdkInc 'km')", "/I$(Join-Path $wdkInc 'shared')",
             "/I$(Join-Path $sdkInc 'shared')", "/I$(Join-Path $sdkInc 'ucrt')", "/I$(Join-Path $sdkInc 'um')")
$defs = @('/D_AMD64_', '/DAMD64', '/D_WIN64', '/DNT', '/DPOOL_NX_OPTIN=0', '/D_CRT_SECURE_NO_WARNINGS')

$objs = @()
foreach ($f in @('main.cpp', 'hde64.c')) {
    $o = Join-Path $work ([IO.Path]::GetFileNameWithoutExtension($f) + '.obj')
    $std = if ($f.EndsWith('.cpp')) { @('/std:c++17', '/TP') } else { @('/TC') }
    & $cl /nologo /c /kernel /GS- /Gs9999999 /O2 /Oi @defs @std @incArgs "/Fo$o" (Join-Path $here $f)
    if ($LASTEXITCODE -ne 0) { throw "echec compilation $f" }
    $objs += $o
}

& $link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /MACHINE:X64 /NODEFAULTLIB /RELEASE `
      "/OUT:$here\VnSpoofer.sys" @objs "/LIBPATH:$wdkLib" "/LIBPATH:$sdkLib" `
      ntoskrnl.lib wdm.lib hal.lib BufferOverflowK.lib
if ($LASTEXITCODE -ne 0) { throw 'echec link' }
Write-Host "OK -> $here\VnSpoofer.sys"

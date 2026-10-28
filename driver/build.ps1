$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$work = Join-Path $here '.wdk'
New-Item -ItemType Directory -Force $work | Out-Null
$sdkRoot = 'C:\Program Files (x86)\Windows Kits\10'

# --- SDK : on prend celui du systeme qui a um\excpt.h (le paquet nuget n'a pas um) ---
$sdkCand = Get-ChildItem "$sdkRoot\Include" -Directory -ErrorAction SilentlyContinue |
           Where-Object { Test-Path (Join-Path $_.FullName 'um\excpt.h') } |
           Sort-Object Name -Descending
if (-not $sdkCand) {
    Get-ChildItem "$sdkRoot\Include" -Recurse -Filter excpt.h -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "excpt.h: $($_.FullName)" }
    throw 'aucun SDK systeme avec um\excpt.h'
}
$sInc = $sdkCand[0].FullName
$ver  = $sdkCand[0].Name
Write-Host "SDK $ver"

# --- WDK nuget epingle sur la meme version que le SDK ---
$dir = Join-Path $work 'wdk'
if (-not (Test-Path $dir)) {
    $idx = 'https://api.nuget.org/v3-flatcontainer/microsoft.windows.wdk.x64/index.json'
    $all = (Invoke-RestMethod $idx).versions
    $maj = ($ver -split "`.")[0..2] -join "`."
    Write-Host "recherche WDK $maj.*"
    $pick = $all | Where-Object { $_ -like "$maj.*" } | Select-Object -Last 1
    if (-not $pick) { Write-Host "::warning::aucune version $maj, fallback"; $pick = $all | Select-Object -Last 1 }
    Write-Host "WDK nuget $pick"
    $zip = Join-Path $work 'wdk.zip'
    Invoke-WebRequest "https://api.nuget.org/v3-flatcontainer/microsoft.windows.wdk.x64/$pick/microsoft.windows.wdk.x64.$pick.nupkg" -OutFile $zip
    Expand-Archive $zip -DestinationPath $dir -Force
}
$kh = Get-ChildItem $dir -Recurse -Filter ntddk.h | Where-Object { $_.FullName -match '\\km\\' } | Select-Object -First 1
if (-not $kh) { throw 'ntddk.h introuvable (wdk nuget)' }
$wVer = $kh.Directory.Parent.Name
$wRoot = $kh.Directory.Parent.Parent.Parent.FullName
$wInc = Join-Path $wRoot "Include\$wVer"
$wLib = Join-Path $wRoot "Lib\$wVer\km\x64"
Write-Host "WDK $wVer"
if ($wVer -ne $ver) { Write-Host "::warning::WDK $wVer != SDK $ver" }

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$cl = & $vswhere -latest -products * -find 'VC\Tools\MSVC\**\bin\Hostx64\x64\cl.exe' | Select-Object -First 1
if (-not $cl) { throw 'cl.exe introuvable' }
$link = Join-Path (Split-Path $cl) 'link.exe'
$msvc = Split-Path (Split-Path (Split-Path $cl))

$incDirs = @((Join-Path $msvc 'include'), (Join-Path $wInc 'km'), (Join-Path $wInc 'shared'),
             (Join-Path $sInc 'ucrt'), (Join-Path $sInc 'shared'), (Join-Path $sInc 'um')) |
           Where-Object { Test-Path $_ }
foreach ($d in $incDirs) { Write-Host "  /I $d" }

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
    & $cl "@$rsp" (Join-Path $here $f)
    if ($LASTEXITCODE -ne 0) { throw "echec compilation $f" }
    $objs += $o
}

$lrsp = Join-Path $work 'link.rsp'
$ll = @('/nologo', '/DRIVER', '/SUBSYSTEM:NATIVE', '/ENTRY:DriverEntry', '/MACHINE:X64', '/NODEFAULTLIB', '/RELEASE',
        "/OUT:`"$here\VnSpoofer.sys`"")
foreach ($d in @($wLib, (Join-Path $sdkRoot "Lib\$ver\km\x64"), (Join-Path $msvc 'lib\x64'))) { if (Test-Path $d) { $ll += "/LIBPATH:`"$d`"" } }
$ll += $objs; $ll += @('ntoskrnl.lib', 'wdm.lib', 'hal.lib', 'BufferOverflowK.lib')
Set-Content $lrsp $ll -Encoding ASCII
& $link "@$lrsp"
if ($LASTEXITCODE -ne 0) { throw 'echec link' }
Write-Host "OK -> $here\VnSpoofer.sys"

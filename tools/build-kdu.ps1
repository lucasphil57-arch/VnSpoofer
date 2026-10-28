$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$work = Join-Path $PSScriptRoot '.kdu'
if (-not (Test-Path $work)) { git clone --depth 1 https://github.com/hfiref0x/KDU $work }

$msb = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1
if (-not $msb) { throw 'msbuild introuvable' }

function B($proj, $dir, $plat, $sol) {
    Push-Location (Join-Path $work $dir)
    & $msb $proj /m /p:Configuration=Release "/p:Platform=$plat" /p:PlatformToolset=v145 "/p:SolutionDir=$sol" | Out-Null
    $rc = $LASTEXITCODE
    if ($rc -ne 0) {
        & $msb $proj /m /p:Configuration=Release "/p:Platform=$plat" /p:PlatformToolset=v143 "/p:SolutionDir=$sol" | Out-Null
        $rc = $LASTEXITCODE
    }
    Pop-Location
    if ($rc -ne 0) { throw "echec build $proj" }
}

B 'Taigei.vcxproj' 'Source\Taigei' 'Win32' '..\'
B 'Taigei.vcxproj' 'Source\Taigei' 'x64' '..\'
B 'PCOMP.vcxproj' 'Source\Utils\PCOMP' 'x64' '..\..\'

Push-Location $work
Copy-Item 'Source\Taigei\output\Win32\Release\Taigei32.dll' '.\Taigei32.dll' -Force
Copy-Item 'Source\Taigei\output\x64\Release\Taigei64.dll' '.\SB_SMBUS_SDK.dll' -Force
& 'Source\Utils\PCOMP\output\x64\Release\PCOMP.exe' '.\Taigei32.dll' 4130237664
& 'Source\Utils\PCOMP\output\x64\Release\PCOMP.exe' '.\SB_SMBUS_SDK.dll' 4130237664
Copy-Item '.\Taigei32.bin' 'Source\Hamakaze\res\Taigei32.bin' -Force
Copy-Item '.\SB_SMBUS_SDK.bin' 'Source\Hamakaze\res\SB_SMBUS_SDK.bin' -Force
Pop-Location

B 'Tanikaze.vcxproj' 'Source\Tanikaze' 'x64' '..\'
B 'KDU.vcxproj' 'Source\Hamakaze' 'x64' '..\'

New-Item -ItemType Directory -Force "$root\app\res" | Out-Null
Copy-Item "$work\Source\Hamakaze\output\x64\Release\kdu.exe" "$root\app\res\kdu.exe" -Force
Copy-Item "$work\Source\Tanikaze\output\x64\Release\drv64.dll" "$root\app\res\drv64.dll" -Force
Write-Host 'KDU construit'

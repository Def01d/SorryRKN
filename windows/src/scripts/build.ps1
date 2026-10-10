param([switch]$RuntimeOnly)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    New-Item -ItemType Directory -Force dist|Out-Null
    if (-not (Test-Path 'runtime/python/python.exe') -or -not (Test-Path 'runtime/zapret/bin/winws.exe')) {
        $archive=Join-Path $root 'dist/runtime-baseline.zip'
        Invoke-WebRequest 'https://raw.githubusercontent.com/Def01d/SorryRKN/windows-v1.0.0/windows/SorryRKN-Windows-1.0.0.zip' -OutFile $archive
        if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne '63352bcffc05fd180ad9f2a179ed2770978bff24090abfe040e62503a2693986') {throw 'Baseline runtime checksum mismatch'}
        $baseline=Join-Path $root 'dist/baseline'
        Expand-Archive $archive -DestinationPath $baseline -Force
        New-Item -ItemType Directory -Force runtime|Out-Null
        foreach ($name in @('python','zapret')) {Copy-Item "$baseline/SorryRKN/runtime/$name" runtime -Recurse -Force}
    }
    if ($RuntimeOnly) {return}
    & (Join-Path $PSScriptRoot 'resources.ps1')
    $env:GOOS='windows';$env:GOARCH='amd64'
    go build -trimpath -ldflags '-H windowsgui -s -w' -o dist/SorryRKN.exe ./cmd/sorryrkn
    if ($LASTEXITCODE -ne 0) {throw 'Go build failed'}
    go build -trimpath -ldflags '-s -w' -o dist/check-network.exe ./cmd/check-network
    if ($LASTEXITCODE -ne 0) {throw 'Diagnostics build failed'}
    $package=Join-Path $root 'dist/package/SorryRKN'
    $expectedPackage=[IO.Path]::GetFullPath((Join-Path $root 'dist/package/SorryRKN'))
    if ([IO.Path]::GetFullPath($package) -ne $expectedPackage) {throw 'Unexpected package path'}
    if (Test-Path -LiteralPath $package) {Remove-Item -LiteralPath $package -Recurse -Force}
    New-Item -ItemType Directory -Force $package|Out-Null
    Copy-Item dist/SorryRKN.exe,dist/check-network.exe,README.md,VALIDATION.md $package
    Copy-Item runtime,licenses $package -Recurse
    $packageRoot=[IO.Path]::GetFullPath($package).TrimEnd('\')+'\'
    Get-ChildItem "$package/runtime" -Directory -Recurse -Filter '__pycache__' | ForEach-Object {
        $cachePath=[IO.Path]::GetFullPath($_.FullName)
        if (-not $cachePath.StartsWith($packageRoot,[StringComparison]::OrdinalIgnoreCase)) {throw 'Unexpected cache path'}
        Remove-Item -LiteralPath $cachePath -Recurse -Force
    }
    Compress-Archive $package 'dist/SorryRKN-Windows-1.2.0.zip' -Force
    if (Get-Command makensis -ErrorAction SilentlyContinue) {
        makensis /NOCONFIG /INPUTCHARSET UTF8 scripts/installer.nsi
        if ($LASTEXITCODE -ne 0) {throw 'NSIS build failed'}
    } else {Write-Host 'Portable ZIP built. Install NSIS 3 and add makensis to PATH to also build Setup.exe.'}
} finally {Pop-Location}

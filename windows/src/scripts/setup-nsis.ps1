param([string]$ToolsDirectory)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not $ToolsDirectory) { $ToolsDirectory = Join-Path $root 'dist/tools' }
$ToolsDirectory = [IO.Path]::GetFullPath($ToolsDirectory)
New-Item -ItemType Directory -Force $ToolsDirectory | Out-Null

# Official NSIS 3.13 portable archive and SHA-256 published by its SourceForge project.
$version = '3.13'
$expectedHash = 'ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8'
$address = 'https://downloads.sourceforge.net/project/nsis/NSIS%203/3.13/nsis-3.13.zip'
$archive = Join-Path $ToolsDirectory "nsis-$version.zip"
$validArchive = (Test-Path -LiteralPath $archive) -and
    ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -eq $expectedHash)

if (-not $validArchive) {
    Invoke-WebRequest $address -OutFile $archive -UseBasicParsing -TimeoutSec 60
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
        # Some official mirrors serve a small HTML page with a timed download URL.
        # Follow only that project's HTTPS download URL, then verify the same hash.
        if ((Get-Item -LiteralPath $archive).Length -gt 512KB) { throw 'NSIS archive checksum mismatch' }
        $html = Get-Content -LiteralPath $archive -Raw
        $refresh = [regex]::Match($html, '(?i)<meta\s+http-equiv="refresh"\s+content="\d+;\s*url=([^"]+)"')
        if (-not $refresh.Success) { throw 'NSIS archive checksum mismatch; no official download redirect' }
        $redirect = [Uri][Net.WebUtility]::HtmlDecode($refresh.Groups[1].Value)
        if ($redirect.Scheme -ne 'https' -or $redirect.Host -ne 'downloads.sourceforge.net' -or
            $redirect.UserInfo -or -not $redirect.IsDefaultPort -or
            [Uri]::UnescapeDataString($redirect.AbsolutePath) -ne '/project/nsis/NSIS 3/3.13/nsis-3.13.zip') {
            throw 'Unexpected NSIS download redirect'
        }
        Invoke-WebRequest $redirect.AbsoluteUri -OutFile $archive -UseBasicParsing -TimeoutSec 60
    }
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
    throw 'NSIS archive checksum mismatch'
}

$expanded = Join-Path $ToolsDirectory "nsis-$version-verified"
Expand-Archive -LiteralPath $archive -DestinationPath $expanded -Force
$compilerDirectory = Join-Path $expanded "nsis-$version"
$compiler = Join-Path $compilerDirectory 'makensis.exe'
$compilerVersion = & $compiler /VERSION
if ($LASTEXITCODE -ne 0 -or "$compilerVersion".Trim() -ne "v$version") { throw 'Unexpected NSIS compiler version' }
$env:PATH = $compilerDirectory + [IO.Path]::PathSeparator + $env:PATH
if ($env:GITHUB_PATH) { Add-Content -LiteralPath $env:GITHUB_PATH -Value $compilerDirectory -Encoding utf8 }
Write-Host "Verified NSIS $version portable, SHA256 $expectedHash"
Write-Output $compiler

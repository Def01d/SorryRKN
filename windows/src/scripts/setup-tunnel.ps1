# Restore the unmodified official engine and bundle its upstream source and license.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$engine = Join-Path $root 'runtime/tunnel'
$cache = Join-Path $root 'dist/tunnel-cache'
New-Item -ItemType Directory -Force $engine,$cache | Out-Null
function Get-PinnedArchive($url, $path, $hash) {
    if (-not (Test-Path -LiteralPath $path) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $hash) {
        Invoke-WebRequest -Uri $url -OutFile $path
    }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $hash) {
        throw 'VPN runtime archive checksum mismatch'
    }
}
$archive = Join-Path $cache 'sing-box-1.14.4-windows-amd64.zip'
Get-PinnedArchive 'https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-windows-amd64.zip' $archive '99185D75D314A07DBBA4A130C8AD986CBEB629A07927975636B341CA61F991DF'
$source = Join-Path $engine 'sing-box-1.14.4-source.zip'
Get-PinnedArchive 'https://codeload.github.com/SagerNet/sing-box/zip/refs/tags/v1.14.4' $source '9037718F85B67A004517C6A9190B98C68483DE643F57C62EB6C889E01BEAE4BC'
Expand-Archive -LiteralPath $archive -DestinationPath $cache -Force
$upstream = Join-Path $cache 'sing-box-1.14.4-windows-amd64'
foreach ($file in @('sing-box.exe','libcronet.dll','LICENSE')) {
    Copy-Item -LiteralPath (Join-Path $upstream $file) -Destination $engine -Force
}
$env:GOOS='windows'
$env:GOARCH='amd64'
go -C $root build -trimpath -ldflags '-s -w' -o (Join-Path $engine 'signal.exe') ./cmd/tunnel-signal
if ($LASTEXITCODE -ne 0) {throw 'VPN console helper build failed'}

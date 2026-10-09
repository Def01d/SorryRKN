$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64 --out cmd/sorryrkn/rsrc --manifest gui --admin --icon resources/icon.png --product-version 1.1.0 --file-version 1.1.0 --file-description SorryRKN --product-name SorryRKN --original-filename SorryRKN.exe
    if ($LASTEXITCODE -ne 0) {throw 'Windows resource generation failed'}
} finally {Pop-Location}

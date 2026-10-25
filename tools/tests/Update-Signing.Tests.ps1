$ErrorActionPreference='Stop'
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('update-signing-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot|Out-Null
$tool=(Join-Path $PSScriptRoot '../Update-Signing.ps1')
$trust=Join-Path $testRoot 'public.json';$key=Join-Path $testRoot 'first.dpapi';$restored=Join-Path $testRoot 'restored.dpapi'
$backup=Join-Path $testRoot 'portable.key-backup.json';$manifest=Join-Path $testRoot 'manifest.json'
$global:SorryRKNBackupTestPassword=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
function Read-Host {param([string]$Prompt,[switch]$AsSecureString) ConvertTo-SecureString $global:SorryRKNBackupTestPassword -AsPlainText -Force}
& $tool -Action Create -PrivateKeyPath $key -PublicTrustPath $trust | Out-Null
[IO.File]::WriteAllText($manifest,'{"versionCode":1,"name":"test"}',[Text.UTF8Encoding]::new($false))
& $tool -Action Sign -ManifestPath $manifest -PrivateKeyPath $key -PublicTrustPath $trust | Out-Null
& $tool -Action Backup -PrivateKeyPath $key -PublicTrustPath $trust -BackupPath $backup | Out-Null
& $tool -Action Restore -PrivateKeyPath $restored -PublicTrustPath $trust -BackupPath $backup | Out-Null
& $tool -Action Sign -ManifestPath $manifest -PrivateKeyPath $restored -PublicTrustPath $trust | Out-Null
$signed=Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
$public=Get-Content -LiteralPath $trust -Raw | ConvertFrom-Json
if ($signed.keyId -ne $public.key_id) {throw 'Restored key identity changed'}
$global:SorryRKNBackupTestPassword='wrong-password-that-is-not-the-backup-password'
$failed=$false
try {& $tool -Action Restore -PrivateKeyPath (Join-Path $testRoot 'must-not-exist.dpapi') -PublicTrustPath $trust -BackupPath $backup | Out-Null} catch {$failed=$true}
if (-not $failed -or (Test-Path -LiteralPath (Join-Path $testRoot 'must-not-exist.dpapi'))) {throw 'Wrong password accepted'}
$global:SorryRKNBackupTestPassword=$null
Write-Output '{"key_create_sign_backup_restore":"PASS","identity_preserved":true,"wrong_password_rejected":true,"production_key_used":false}'

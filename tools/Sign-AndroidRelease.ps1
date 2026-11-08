#requires -Version 7.4
param(
    [ValidateSet('Create','Sign')][string]$Action='Sign',
    [string]$KeyDirectory=(Join-Path $env:LOCALAPPDATA 'SorryRKN-maintainer/android-production'),
    [string]$BackupDirectory,
    [switch]$UseRecoveryBackup,
    [switch]$TestApk,
    [string]$PublicIdentityPath=(Join-Path $PSScriptRoot '../android/signing-identity.json'),
    [string]$InputApk,
    [string]$OutputApk,
    [string]$Distro='Ubuntu',
    [string]$BuildTools='/home/pepsi/.local/share/sorryrkn-sdk/build-tools/35.0.0'
)
$ErrorActionPreference='Stop'
function Protect-Directory([string]$Path) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    & icacls.exe $Path /inheritance:r /grant:r "*$($sid.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' /q | Out-Null
    if($LASTEXITCODE -ne 0) {throw 'Cannot protect the private signing directory'}
}
$keystore=Join-Path $KeyDirectory 'signing.keystore'
$passwordFile=Join-Path $KeyDirectory 'password.dpapi'
$identityFile=Join-Path $KeyDirectory 'identity.json'
$password=$null;$raw=$null
try {
    if($Action -eq 'Create') {
        if(Test-Path -LiteralPath $PublicIdentityPath) {throw 'A production identity is already published. Restore its original key instead of creating a replacement.'}
        if(-not $BackupDirectory) {throw 'An owner-private backup directory outside Git is required'}
        if((Test-Path -LiteralPath $keystore) -or (Test-Path -LiteralPath $identityFile) -or
           ((Test-Path -LiteralPath $BackupDirectory) -and @(Get-ChildItem -LiteralPath $BackupDirectory -Force).Count -gt 0)) {throw 'Refusing to replace an existing key or backup'}
        $repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')+'\'
        foreach($target in @($KeyDirectory,$BackupDirectory)) {
            if([IO.Path]::GetFullPath($target).StartsWith($repo,[StringComparison]::OrdinalIgnoreCase)) {throw 'Signing material must remain outside the repository'}
            Protect-Directory $target
        }
        if(Test-Path -LiteralPath $passwordFile) {
            $raw=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($passwordFile),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
            $password=[Text.Encoding]::UTF8.GetString($raw)
        } else {
            $password=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
            $raw=[Text.Encoding]::UTF8.GetBytes($password)
            [IO.File]::WriteAllBytes($passwordFile,[Security.Cryptography.ProtectedData]::Protect($raw,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
        }
    } elseif($UseRecoveryBackup) {
        if(-not $BackupDirectory) {throw 'BackupDirectory is required'}
        $recovery=Get-Content -LiteralPath (Join-Path $BackupDirectory 'recovery.json') -Raw | ConvertFrom-Json
        $password=$recovery.password;$keystore=Join-Path $BackupDirectory 'signing.keystore'
        $identityFile=Join-Path $BackupDirectory 'identity.json'
    } else {
        $raw=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($passwordFile),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
        $password=[Text.Encoding]::UTF8.GetString($raw)
    }
    $bridge=Join-Path $PSScriptRoot 'android-sign.py'
    $bridge=[IO.Path]::GetFullPath($bridge).Replace('\','/')
    if($bridge -notmatch '^([A-Za-z]):/(.*)$') {throw 'The WSL signing bridge requires a drive path'}
    $linuxBridge='/mnt/'+$Matches[1].ToLowerInvariant()+'/'+$Matches[2]
    $request=@{action=$Action.ToLowerInvariant();password=$password;keystore=$keystore;build_tools=$BuildTools}
    if($Action -eq 'Sign') {
        if(-not $InputApk -or -not $OutputApk) {throw 'InputApk and a new OutputApk are required'}
        $request.input=[IO.Path]::GetFullPath($InputApk);$request.output=[IO.Path]::GetFullPath($OutputApk)
        $request.application_id='io.github.def01d.sorryrkn'+$(if($TestApk){'.test'}else{''})
    }
    $response=($request | ConvertTo-Json -Compress) | & wsl.exe -d $Distro -- python3 $linuxBridge
    if($LASTEXITCODE -ne 0) {throw 'Android signing operation failed'}
    $fingerprint=($response | ConvertFrom-Json).certificate_sha256
    if($fingerprint -notmatch '^[0-9a-f]{64}$') {throw 'Invalid signing certificate response'}
    if($Action -eq 'Create') {
        $identity=@{application_id='io.github.def01d.sorryrkn';alias='sorryrkn-production';certificate_sha256=$fingerprint;created_utc=[DateTime]::UtcNow.ToString('o')}
        [IO.File]::WriteAllText($identityFile,($identity|ConvertTo-Json)+"`n",[Text.UTF8Encoding]::new($false))
        Copy-Item -LiteralPath $keystore,$passwordFile,$identityFile -Destination $BackupDirectory
        # The recovery kit is portable across Windows profiles. Its password is
        # intentionally recoverable by the owner; keep the entire ACL-protected
        # directory private and store an offline copy separately.
        [IO.File]::WriteAllText((Join-Path $BackupDirectory 'recovery.json'),(@{schema=1;alias='sorryrkn-production';password=$password;certificate_sha256=$fingerprint}|ConvertTo-Json)+"`n",[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $BackupDirectory 'README.txt'),"PRIVATE ANDROID SIGNING RECOVERY KIT. Never publish or commit this folder. recovery.json contains the keystore password. Keep an offline copy. The same signing key is required for all future updates of io.github.def01d.sorryrkn.`n",[Text.UTF8Encoding]::new($false))
    } else {
        $identity=Get-Content -LiteralPath $identityFile -Raw | ConvertFrom-Json
        if($fingerprint -cne $identity.certificate_sha256) {throw 'Signing identity changed'}
        $published=Get-Content -LiteralPath $PublicIdentityPath -Raw | ConvertFrom-Json
        if($fingerprint -cne $published.certificate_sha256 -or $published.application_id -cne 'io.github.def01d.sorryrkn') {throw 'Key does not match the published Android identity'}
    }
    Write-Output "Android production certificate SHA-256: $fingerprint"
} finally {
    $password=$null;$request=$null;$recovery=$null
    if($raw) {[Array]::Clear($raw,0,$raw.Length)}
}

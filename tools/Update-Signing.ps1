param(
    [ValidateSet('Create','Sign','Backup')][string]$Action='Sign',
    [string]$ManifestPath,
    [string]$PrivateKeyPath=(Join-Path $env:LOCALAPPDATA 'SorryRKN-maintainer/keys/updates-v1.dpapi'),
    [string]$PublicTrustPath=(Join-Path $PSScriptRoot '../update-trust.json'),
    [string]$BackupPath,
    [int]$ValidityDays=180
)
$ErrorActionPreference='Stop'
if ($ValidityDays -lt 1 -or $ValidityDays -gt 366) {throw 'Invalid signature lifetime'}
$ecdsa=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
$private=$null
try {
    if ($Action -eq 'Create') {
        if (Test-Path -LiteralPath $PrivateKeyPath) {throw 'Signing key already exists; refusing to replace it'}
        $private=$ecdsa.ExportPkcs8PrivateKey()
        $protected=[Security.Cryptography.ProtectedData]::Protect($private,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
        New-Item -ItemType Directory -Force (Split-Path $PrivateKeyPath -Parent) | Out-Null
        [IO.File]::WriteAllBytes($PrivateKeyPath,$protected)
    } else {
        $private=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($PrivateKeyPath),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
        $consumed=0;$ecdsa.ImportPkcs8PrivateKey($private,[ref]$consumed)
        if ($consumed -ne $private.Length) {throw 'Invalid private key file'}
    }
    $public=$ecdsa.ExportSubjectPublicKeyInfo()
    $keyID=([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($public))).ToLowerInvariant().Substring(0,32)
    $trust=@{schema=1;algorithm='ecdsa-p256-sha256';key_id=$keyID;public_key=[Convert]::ToBase64String($public)}
    if ($Action -eq 'Create') {
        [IO.File]::WriteAllText([IO.Path]::GetFullPath($PublicTrustPath),($trust|ConvertTo-Json).Replace("`r`n","`n")+"`n",[Text.UTF8Encoding]::new($false))
        Write-Output "Created owner-local DPAPI signing key; public key id: $keyID"
    } elseif ($Action -eq 'Sign') {
        if (-not $ManifestPath) {throw 'ManifestPath is required'}
        $expected=Get-Content -LiteralPath $PublicTrustPath -Raw | ConvertFrom-Json
        if ($expected.key_id -ne $keyID -or $expected.public_key -ne $trust.public_key) {throw 'Wrong signing key'}
        $value=Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -AsHashtable
        foreach ($field in @('signed','signature','keyId','signedAt','expires')) {$value.Remove($field)|Out-Null}
        $payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 30 -Compress)))
        $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();$expires=$now+[long]$ValidityDays*86400
        $message="SorryRKN-Envelope-v1`n$keyID`n$now`n$expires`n$payload"
        $signature=$ecdsa.SignData([Text.Encoding]::UTF8.GetBytes($message),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
        $value.signed=$payload;$value.keyId=$keyID;$value.signedAt=$now;$value.expires=$expires;$value.signature=[Convert]::ToBase64String($signature)
        [IO.File]::WriteAllText([IO.Path]::GetFullPath($ManifestPath),($value|ConvertTo-Json -Depth 30).Replace("`r`n","`n")+"`n",[Text.UTF8Encoding]::new($false))
        Write-Output "Signed $([IO.Path]::GetFileName($ManifestPath)); key id: $keyID"
    } else {
        if (-not $BackupPath -or (Test-Path -LiteralPath $BackupPath)) {throw 'A new BackupPath is required'}
        $secure=Read-Host 'Password for portable encrypted signing-key backup' -AsSecureString
        $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try {
            $password=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
            if ($password.Length -lt 12) {throw 'Use at least 12 characters'}
            $salt=[Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
            $nonce=[Security.Cryptography.RandomNumberGenerator]::GetBytes(12)
            $derive=[Security.Cryptography.Rfc2898DeriveBytes]::new($password,$salt,600000,[Security.Cryptography.HashAlgorithmName]::SHA256)
            $key=$derive.GetBytes(32);$cipher=[byte[]]::new($private.Length);$tag=[byte[]]::new(16)
            $aes=[Security.Cryptography.AesGcm]::new($key,16)
            try {$aes.Encrypt($nonce,$private,$cipher,$tag)} finally {$aes.Dispose();$derive.Dispose();[Array]::Clear($key,0,$key.Length)}
            $backup=@{schema=1;algorithm='PBKDF2-SHA256/AES-256-GCM';iterations=600000;key_id=$keyID;salt=[Convert]::ToBase64String($salt);nonce=[Convert]::ToBase64String($nonce);ciphertext=[Convert]::ToBase64String($cipher);tag=[Convert]::ToBase64String($tag)}
            [IO.File]::WriteAllText([IO.Path]::GetFullPath($BackupPath),($backup|ConvertTo-Json).Replace("`r`n","`n")+"`n",[Text.UTF8Encoding]::new($false))
            Write-Output 'Portable encrypted backup created. Keep its password separately.'
        } finally {[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer);$password=$null;$secure.Dispose()}
    }
} finally {if ($private) {[Array]::Clear($private,0,$private.Length)};if ($ecdsa) {$ecdsa.Dispose()}}

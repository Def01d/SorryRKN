param([Parameter(Mandatory=$true)][string]$AppDir,[string]$InstallerPath)
$ErrorActionPreference = 'Stop'
$AppDir = (Resolve-Path $AppDir).Path
$exe = Join-Path $AppDir 'SorryRKN.exe'
$settings = Join-Path $env:LOCALAPPDATA 'SorryRKN'
$results = @{}
$p = Start-Process $exe -ArgumentList '--self-test' -PassThru
if (-not $p.WaitForExit(60000)) { $p.Kill(); throw 'Native self-test timed out' }
$report = Get-Content (Join-Path $settings 'self-test.json') -Raw | ConvertFrom-Json
$results.native = $report
foreach ($name in @('secret_ok','dpapi','crypto','telegram_listener','job_cleanup','windivert_open','selective_dns','dns_stopped','winws_started','winws_stopped')) {
    if ($report.$name -ne $true) {
        $results | ConvertTo-Json -Depth 20 | Set-Content 'validation-results.json'
        throw "Native self-test failed: $name; $($report | ConvertTo-Json -Compress)"
    }
}
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class NativeUI {
 [DllImport("user32.dll",EntryPoint="FindWindowW",ExactSpelling=true,CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string cls,string title);
 [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr hwnd,uint message,IntPtr w,IntPtr l);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr hwnd,System.Text.StringBuilder text,int max);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr hwnd,System.Text.StringBuilder text,int max);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hwnd,out uint pid);
 public delegate bool EnumProc(IntPtr hwnd,IntPtr l);
 [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc callback,IntPtr l);
 [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr hwnd,EnumProc callback,IntPtr l);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hwnd);
 [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hwnd,int n);
 [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd,IntPtr dc,uint flags);
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd,out Rect rect);
 public struct Rect {public int left,top,right,bottom;}
}
'@
$configPath = Join-Path $settings 'config.json'
$c = Get-Content $configPath -Raw | ConvertFrom-Json
$c.dpi = $false; $c.telegram = $true; $c.extra_sites = $false; $c.auto_data = $false
$c | ConvertTo-Json | Set-Content -Encoding utf8 $configPath
$p = Start-Process $exe -PassThru
try {
    $hwnd = [IntPtr]::Zero
    for ($i=0;$i -lt 100;$i++) {
        $hwnd = [NativeUI]::FindWindow('SorryRKNWindow','SorryRKN')
        if ($hwnd -ne [IntPtr]::Zero) {break}
        if ($p.HasExited) {throw 'GUI exited before creating its window'}
        Start-Sleep -Milliseconds 200
    }
    if ($hwnd -eq [IntPtr]::Zero) {
        $script:windowDump=New-Object System.Collections.Generic.List[string]
        $script:targetPid=$p.Id
        $children=[NativeUI+EnumProc]{param($h,$l);$t=New-Object System.Text.StringBuilder 1024;[NativeUI]::GetWindowText($h,$t,1024)|Out-Null;$script:windowDump.Add("child: $t");return $true}
        $script:childCallback=$children
        $enumerate=[NativeUI+EnumProc]{param($h,$l);[uint32]$id=0;[NativeUI]::GetWindowThreadProcessId($h,[ref]$id)|Out-Null;if ($id -eq $script:targetPid) {$t=New-Object System.Text.StringBuilder 1024;$cls=New-Object System.Text.StringBuilder 256;[NativeUI]::GetWindowText($h,$t,1024)|Out-Null;[NativeUI]::GetClassName($h,$cls,256)|Out-Null;$script:windowDump.Add("window: $cls / $t");[NativeUI]::EnumChildWindows($h,$script:childCallback,[IntPtr]::Zero)|Out-Null};return $true}
        [NativeUI]::EnumWindows($enumerate,[IntPtr]::Zero)|Out-Null
        $results.window_dump=$script:windowDump
        Write-Host ($results|ConvertTo-Json -Depth 20)
        throw 'Native GUI window not found'
    }
    $results.gui_window = $true
    [NativeUI]::SendMessage($hwnd,0x111,[IntPtr]100,[IntPtr]::Zero) | Out-Null
    $opened=$false
    for ($i=0;$i -lt 100;$i++) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        try { $tcp.Connect('127.0.0.1',1443); $opened=$true } catch {} finally {$tcp.Dispose()}
        if ($opened) {break}; Start-Sleep -Milliseconds 200
    }
    if (-not $opened) {throw 'GUI did not start Telegram'}
    $results.gui_telegram = $true
    [NativeUI]::SendMessage($hwnd,0x10,[IntPtr]::Zero,[IntPtr]::Zero) | Out-Null
    Start-Sleep -Milliseconds 300
    if ($p.HasExited -or [NativeUI]::IsWindowVisible($hwnd)) {throw 'Closing the window did not minimize to tray'}
    $results.tray_background = $true
    [NativeUI]::ShowWindow($hwnd,5) | Out-Null
    try {
        Add-Type -AssemblyName System.Drawing
        $rect=New-Object NativeUI+Rect
        [NativeUI]::GetWindowRect($hwnd,[ref]$rect) | Out-Null
        $bmp=New-Object System.Drawing.Bitmap ($rect.right-$rect.left),($rect.bottom-$rect.top)
        $graphics=[System.Drawing.Graphics]::FromImage($bmp)
        $hdc=$graphics.GetHdc()
        [NativeUI]::PrintWindow($hwnd,$hdc,2) | Out-Null
        $graphics.ReleaseHdc($hdc)
        $bmp.Save("$PWD/windows-screen.png")
        $graphics.Dispose();$bmp.Dispose()
    } catch { $results.screenshot_note=$_.Exception.Message }
    [NativeUI]::SendMessage($hwnd,0x111,[IntPtr]100,[IntPtr]::Zero) | Out-Null
    Start-Sleep -Seconds 2
    $tcp=New-Object System.Net.Sockets.TcpClient
    $stopped=$false
    try {$tcp.Connect('127.0.0.1',1443)}catch{$stopped=$true}finally{$tcp.Dispose()}
    if (-not $stopped) {throw 'Telegram listener remained after GUI stop'}
    $results.gui_stop = $true
    [NativeUI]::SendMessage($hwnd,0x111,[IntPtr]206,[IntPtr]::Zero) | Out-Null
    if (-not $p.WaitForExit(20000)) {throw 'Exit did not stop the application'}
    $results.gui_exit = $true
} finally {
    if (-not $p.HasExited) {$p.Kill()}
    $results | ConvertTo-Json -Depth 20 | Set-Content 'validation-results.json'
}
if ($InstallerPath) {
    try {
        $setup=Start-Process (Resolve-Path $InstallerPath).Path -ArgumentList '/S' -PassThru
        if (-not $setup.WaitForExit(120000) -or $setup.ExitCode -ne 0) {throw 'Installer failed'}
        $installed=(Get-ItemProperty 'HKLM:\Software\SorryRKN').InstallPath
        $installedExe=Join-Path $installed 'SorryRKN.exe'
        if ((Get-FileHash $installedExe).Hash -ne (Get-FileHash $exe).Hash) {throw 'Installed executable differs from portable build'}
        if (-not (Test-Path (Join-Path $installed 'runtime\python\python.exe'))) {throw 'Installer omitted embedded Python'}
        $results.installer=$true
        $p=Start-Process $installedExe -ArgumentList '--self-test' -PassThru
        if (-not $p.WaitForExit(60000)) {$p.Kill();throw 'Installed self-test timed out'}
        $installedReport=Get-Content (Join-Path $settings 'self-test.json') -Raw | ConvertFrom-Json
        foreach ($name in @('crypto','telegram_listener','job_cleanup','windivert_open','selective_dns','dns_stopped','winws_started','winws_stopped')) {
            if ($installedReport.$name -ne $true) {throw "Installed native self-test failed: $name"}
        }
        $results.installed_runtime=$true
        $uninstall=Start-Process (Join-Path $installed 'Uninstall.exe') -ArgumentList '/S' -PassThru
        $uninstall.WaitForExit(60000)|Out-Null
        for ($i=0;$i -lt 100 -and ((Test-Path $installedExe) -or (Test-Path 'HKLM:\Software\SorryRKN'));$i++) {Start-Sleep -Milliseconds 200}
        if ((Test-Path $installedExe) -or (Test-Path 'HKLM:\Software\SorryRKN')) {throw 'Uninstaller left the app or registry entry'}
        if (-not (Test-Path $configPath)) {throw 'Uninstaller deleted user preferences'}
        $results.uninstaller=$true
    } finally {$results | ConvertTo-Json -Depth 20 | Set-Content 'validation-results.json'}
}
Write-Host ($results | ConvertTo-Json -Depth 20)
if (Test-Path 'windows-screen.png') {Write-Host ('SCREENSHOT_BASE64:'+ [Convert]::ToBase64String([IO.File]::ReadAllBytes("$PWD/windows-screen.png")))}

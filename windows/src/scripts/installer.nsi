Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
Name "SorryRKN"
OutFile "../dist/SorryRKN-Windows-1.0.0-Setup.exe"
InstallDir "$PROGRAMFILES64\SorryRKN"
InstallDirRegKey HKLM "Software\SorryRKN" "InstallPath"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
BrandingText "SorryRKN"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\SorryRKN.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Открыть SorryRKN"
!define MUI_FINISHPAGE_RUN_NOTCHECKED
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Russian"
VIProductVersion "1.0.0.0"
VIAddVersionKey /LANG=1049 "ProductName" "SorryRKN"
VIAddVersionKey /LANG=1049 "FileDescription" "SorryRKN Windows Installer"
VIAddVersionKey /LANG=1049 "FileVersion" "1.0.0"
VIAddVersionKey /LANG=1049 "LegalCopyright" "SorryRKN contributors"
Function .onInit
 ${IfNot} ${RunningX64}
  MessageBox MB_OK|MB_ICONSTOP "Эта версия SorryRKN предназначена для Windows 10/11 x64."
  Abort
 ${EndIf}
 SetRegView 64
 loop:
 System::Call 'kernel32::OpenMutexW(i 0x100000, i 0, w "Local\SorryRKN.Windows.1") p.r0'
 ${If} $0 != 0
  System::Call 'kernel32::CloseHandle(p r0)'
  Sleep 2000
  System::Call 'kernel32::OpenMutexW(i 0x100000, i 0, w "Local\SorryRKN.Windows.1") p.r0'
  ${If} $0 != 0
   System::Call 'kernel32::CloseHandle(p r0)'
   MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "Закройте SorryRKN через «Выход» в меню трея, затем повторите установку." IDRETRY loop
   Abort
  ${EndIf}
 ${EndIf}
FunctionEnd
Section "SorryRKN" Main
 SetOutPath "$INSTDIR"
 File "../dist/SorryRKN.exe"
 File "../README.md"
 SetOutPath "$INSTDIR\runtime"
 File /r "../runtime\*.*"
 SetOutPath "$INSTDIR\licenses"
 File /r "../licenses\*.*"
 SetOutPath "$INSTDIR"
 WriteUninstaller "$INSTDIR\Uninstall.exe"
 CreateDirectory "$SMPROGRAMS\SorryRKN"
 CreateShortcut "$SMPROGRAMS\SorryRKN\SorryRKN.lnk" "$INSTDIR\SorryRKN.exe"
 CreateShortcut "$SMPROGRAMS\SorryRKN\Удалить.lnk" "$INSTDIR\Uninstall.exe"
 CreateShortcut "$DESKTOP\SorryRKN.lnk" "$INSTDIR\SorryRKN.exe"
 WriteRegStr HKLM "Software\SorryRKN" "InstallPath" "$INSTDIR"
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SorryRKN" "DisplayName" "SorryRKN"
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SorryRKN" "DisplayVersion" "1.0.0"
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SorryRKN" "UninstallString" '"$INSTDIR\Uninstall.exe"'
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SorryRKN" "DisplayIcon" "$INSTDIR\SorryRKN.exe"
 WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SorryRKN" "NoModify" 1
 WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SorryRKN" "NoRepair" 1
SectionEnd
Function un.onInit
 SetRegView 64
 System::Call 'kernel32::OpenMutexW(i 0x100000, i 0, w "Local\SorryRKN.Windows.1") p.r0'
 ${If} $0 != 0
  System::Call 'kernel32::CloseHandle(p r0)'
  MessageBox MB_OK|MB_ICONEXCLAMATION "Сначала закройте SorryRKN через «Выход» в меню трея."
  Abort
 ${EndIf}
FunctionEnd
Section "Uninstall"
 Delete "$DESKTOP\SorryRKN.lnk"
 RMDir /r "$SMPROGRAMS\SorryRKN"
 Delete "$INSTDIR\SorryRKN.exe"
 Delete "$INSTDIR\README.md"
 RMDir /r "$INSTDIR\runtime"
 RMDir /r "$INSTDIR\licenses"
 Delete "$INSTDIR\Uninstall.exe"
 RMDir "$INSTDIR"
 DeleteRegKey HKLM "Software\SorryRKN"
 DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SorryRKN"
 ; Per-user settings are retained to preserve the Telegram secret on reinstall.
SectionEnd

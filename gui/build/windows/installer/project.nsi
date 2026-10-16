Unicode true

####
## LANyard installer (NSIS). Wails fills in wails_tools.nsh from wails.json
## (product name, version, executable, URI scheme). Product identity lives in
## internal/brand/brand.json; run `go run ./tools/brandsync` after renaming.
##
## What it does beyond copying files:
##   * Start-menu (and desktop) shortcut
##   * registers the custom URI scheme (lanyard://join/...)
##   * adds an inbound Windows Firewall rule for the executable, so players are
##     never confronted with the "Allow access" prompt (removed on uninstall)
##   * stops a running background core before replacing files
##
## The uninstaller removes only the files it installed and then the folder if
## it is empty, never `RMDir /r $INSTDIR`: the folder is whatever the user
## typed on the directory page (it could be D:\Games).
##
## Code signing (SignPath) happens outside this script, see
## .github/workflows/release.yml.
####

!include "wails_tools.nsh"

VIProductVersion "${INFO_PRODUCTVERSION}.0"
VIFileVersion    "${INFO_PRODUCTVERSION}.0"

VIAddVersionKey "CompanyName"     "${INFO_COMPANYNAME}"
VIAddVersionKey "FileDescription" "${INFO_PRODUCTNAME} Installer"
VIAddVersionKey "ProductVersion"  "${INFO_PRODUCTVERSION}"
VIAddVersionKey "FileVersion"     "${INFO_PRODUCTVERSION}"
VIAddVersionKey "LegalCopyright"  "${INFO_COPYRIGHT}"
VIAddVersionKey "ProductName"     "${INFO_PRODUCTNAME}"

ManifestDPIAware true

!include "MUI.nsh"

!define MUI_ICON "..\icon.ico"
!define MUI_UNICON "..\icon.ico"
!define MUI_ABORTWARNING
; Start the app through Explorer so it runs as the user, not elevated like
; the installer (and so does the background core it starts).
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION RunUnelevated

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\..\..\LICENSE"
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE DirectoryLeave
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "SimpChinese"

Name "${INFO_PRODUCTNAME}"
OutFile "..\..\bin\${INFO_PROJECTNAME}-${ARCH}-installer.exe"
InstallDir "$PROGRAMFILES64\${INFO_PRODUCTNAME}"
; Upgrades go where the previous version is (NSIS strips the file name from
; the .exe path), including installs made before the LANyard subfolder rule.
InstallDirRegKey HKLM "${UNINST_KEY}" "DisplayIcon"
ShowInstDetails show

!define FW_RULE "${INFO_PRODUCTNAME}"
; URI scheme for join links. Kept in sync with internal/brand/brand.json "id"
; by tools/brandsync.
!define URI_SCHEME "lanyard"

Function RunUnelevated
   Exec '"$WINDIR\explorer.exe" "$INSTDIR\${PRODUCT_EXECUTABLE}"'
FunctionEnd

; If the user picks a folder that is not already a LANyard folder (for example
; D:\Games), install into a LANyard subfolder of it, unless LANyard is already
; installed right there (an older install: upgrade it in place).
Function DirectoryLeave
   IfFileExists "$INSTDIR\${PRODUCT_EXECUTABLE}" done
   ${GetFileName} "$INSTDIR" $R0
   StrCmp $R0 "${INFO_PRODUCTNAME}" done
   StrCpy $INSTDIR "$INSTDIR\${INFO_PRODUCTNAME}"
   done:
FunctionEnd

Function .onInit
   !insertmacro wails.checkArchitecture
   !insertmacro MUI_LANGDLL_DISPLAY
FunctionEnd

!macro StopRunning
    ; The GUI and its background core are the same executable.
    nsExec::Exec 'taskkill /F /IM "${PRODUCT_EXECUTABLE}"'
    Pop $0
    Sleep 500
!macroend

Section
    !insertmacro wails.setShellContext

    !insertmacro StopRunning
    !insertmacro wails.webview2runtime

    SetOutPath $INSTDIR
    !insertmacro wails.files

    CreateShortcut "$SMPROGRAMS\${INFO_PRODUCTNAME}.lnk" "$INSTDIR\${PRODUCT_EXECUTABLE}"
    CreateShortCut "$DESKTOP\${INFO_PRODUCTNAME}.lnk" "$INSTDIR\${PRODUCT_EXECUTABLE}"

    !insertmacro wails.associateFiles
    !insertmacro wails.associateCustomProtocols
    ; wails_tools.nsh (regenerated on every build) leaves the program path
    ; unquoted; quote it so installs under paths with spaces work reliably.
    WriteRegStr SHELL_CONTEXT "Software\Classes\${URI_SCHEME}\shell\open\command" "" '"$INSTDIR\${PRODUCT_EXECUTABLE}" "%1"'

    ; Inbound firewall rule for the executable (all profiles: many PCs label
    ; home networks "Public"). Delete first so reinstalls don't duplicate it.
    nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="${FW_RULE}"'
    Pop $0
    nsExec::ExecToLog 'netsh advfirewall firewall add rule name="${FW_RULE}" dir=in action=allow program="$INSTDIR\${PRODUCT_EXECUTABLE}" enable=yes profile=any'
    Pop $0

    !insertmacro wails.writeUninstaller
SectionEnd

Section "uninstall"
    !insertmacro wails.setShellContext

    !insertmacro StopRunning

    nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="${FW_RULE}"'
    Pop $0

    ; WebView2 data lives in the user's roaming AppData, not ProgramData.
    SetShellVarContext current
    RMDir /r "$APPDATA\${PRODUCT_EXECUTABLE}"
    !insertmacro wails.setShellContext

    ; Only what the installer put there; the folder goes only if now empty.
    Delete "$INSTDIR\${PRODUCT_EXECUTABLE}"

    Delete "$SMPROGRAMS\${INFO_PRODUCTNAME}.lnk"
    Delete "$DESKTOP\${INFO_PRODUCTNAME}.lnk"

    !insertmacro wails.unassociateFiles
    !insertmacro wails.unassociateCustomProtocols

    !insertmacro wails.deleteUninstaller
    RMDir $INSTDIR
SectionEnd

Unicode true

####
## LANyard installer (NSIS). Wails fills in wails_tools.nsh from wails.json
## (product name, version, executable, URI scheme). Product identity lives in
## internal/brand/brand.json; run `go run ./tools/brandsync` after renaming.
##
## What it does beyond copying files:
##   * Start-menu (and desktop) shortcut
##   * registers the custom URI scheme (lanyard://join/...) via wails.associateCustomProtocols
##   * adds an inbound Windows Firewall rule for the executable, so players are
##     never confronted with the "Allow access" prompt (removed on uninstall)
##   * stops a running background core before replacing files
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
!define MUI_FINISHPAGE_RUN "$INSTDIR\${PRODUCT_EXECUTABLE}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\..\..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "SimpChinese"

Name "${INFO_PRODUCTNAME}"
OutFile "..\..\bin\${INFO_PROJECTNAME}-${ARCH}-installer.exe"
InstallDir "$PROGRAMFILES64\${INFO_PRODUCTNAME}"
ShowInstDetails show

!define FW_RULE "${INFO_PRODUCTNAME}"

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

    RMDir /r "$AppData\${PRODUCT_EXECUTABLE}" # WebView2 data
    RMDir /r $INSTDIR

    Delete "$SMPROGRAMS\${INFO_PRODUCTNAME}.lnk"
    Delete "$DESKTOP\${INFO_PRODUCTNAME}.lnk"

    !insertmacro wails.unassociateFiles
    !insertmacro wails.unassociateCustomProtocols

    !insertmacro wails.deleteUninstaller
SectionEnd

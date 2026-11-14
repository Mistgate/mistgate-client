; What the installer does besides copying files: the background service, and cleaning up after itself.
; The service binary registers and removes itself (mistgate-clientd install / uninstall).

Var MgFresh ; 1 when nothing of Mistgate was in the folder before this install

!macro NSIS_HOOK_PREINSTALL
  StrCpy $MgFresh 1
  ; an update: stop and remove the running service so its file can be replaced (the VPN goes down with it)
  ${If} ${FileExists} "$INSTDIR\mistgate-clientd.exe"
    StrCpy $MgFresh 0
    ; Only the file of the install this machine has on record is run, with these (administrator's) rights. A file of
    ; that name found in any other folder may be anybody's: there the service is stopped and removed by its name.
    ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCTNAME}" "InstallLocation"
    ${If} $0 == "$INSTDIR"
    ${OrIf} $0 == '"$INSTDIR"'
      nsExec::ExecToLog '"$INSTDIR\mistgate-clientd.exe" uninstall'
    ${Else}
      nsExec::ExecToLog 'sc.exe stop MistgateClient'
      Pop $0
      nsExec::ExecToLog 'sc.exe delete MistgateClient'
    ${EndIf}
    Pop $0
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; the setup window's "Desktop shortcut" switch, off (a silent install makes the shortcut on its own)
  ClearErrors
  ${GetOptions} $CMDLINE "/NODESK" $R0
  ${IfNot} ${Errors}
    Delete "$DESKTOP\${PRODUCTNAME}.lnk"
  ${EndIf}
  ; mistgate:// links (a subscription page's "add to the app" button) open the app
  WriteRegStr HKLM "Software\Classes\mistgate" "" "URL:Mistgate"
  WriteRegStr HKLM "Software\Classes\mistgate" "URL Protocol" ""
  WriteRegStr HKLM "Software\Classes\mistgate\shell\open\command" "" '"$INSTDIR\mistgate.exe" "%1"'
  ; The folder holds a program that runs as the system: whatever folder was chosen, only administrators and the
  ; system may change what is in it; everyone else reads and runs.
  nsExec::ExecToLog 'icacls "$INSTDIR" /setowner *S-1-5-32-544 /T /C /Q'
  Pop $0
  nsExec::ExecToLog 'icacls "$INSTDIR" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /C /Q'
  Pop $0
  nsExec::ExecToLog 'icacls "$INSTDIR\*" /reset /T /C /Q'
  Pop $0
  ; The service serves only the Windows accounts it was told to: the setup window names the account it runs as
  ; (the permission prompt may have been answered by another). The service's program checks what it is given.
  ClearErrors
  ${GetOptions} $CMDLINE "/USER=" $R1
  ${IfNot} ${Errors}
    nsExec::ExecToLog '"$INSTDIR\mistgate-clientd.exe" allow "$R1"'
    Pop $0
  ${EndIf}
  ClearErrors
  nsExec::ExecToLog '"$INSTDIR\mistgate-clientd.exe" install'
  Pop $0
  ${If} $0 != "0"
    ${If} ${Silent}
      ; run by the setup window, which shows the failure: it reads the exit code. A first install is taken back,
      ; as that window says; an update leaves the new version's files in place.
      IntOp $1 $0 + 0
      ${If} $1 = 0
        StrCpy $1 3
      ${EndIf}
      SetErrorLevel $1
      ${If} $MgFresh = 1
        ExecWait '"$INSTDIR\uninstall.exe" /S _?=$INSTDIR'
        Delete "$INSTDIR\uninstall.exe"
        RMDir "$INSTDIR"
      ${EndIf}
    ${Else}
      MessageBox MB_ICONEXCLAMATION|MB_OK "The Mistgate background service could not be started (code $0). Mistgate will not be able to connect until it runs."
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog '"$INSTDIR\mistgate-clientd.exe" uninstall'
  ; "start with Windows", written by the app for this user
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Mistgate"
  DeleteRegKey HKLM "Software\Classes\mistgate"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; subscriptions and settings go only when the user ticks "delete application data"; an update keeps them
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    ReadEnvStr $0 PROGRAMDATA
    RMDir /r "$0\Mistgate"
  ${EndIf}
!macroend

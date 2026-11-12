; What the installer does besides copying files: the background service, and cleaning up after itself.
; The service binary registers and removes itself (mistgate-clientd install / uninstall).

Var MgFresh ; 1 when nothing of Mistgate was in the folder before this install

!macro NSIS_HOOK_PREINSTALL
  StrCpy $MgFresh 1
  ; an update: stop and remove the running service so its file can be replaced (the VPN goes down with it)
  ${If} ${FileExists} "$INSTDIR\mistgate-clientd.exe"
    StrCpy $MgFresh 0
    nsExec::ExecToLog '"$INSTDIR\mistgate-clientd.exe" uninstall'
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; the setup window's "Desktop shortcut" switch, off (a silent install makes the shortcut on its own)
  ClearErrors
  ${GetOptions} $CMDLINE "/NODESK" $R0
  ${IfNot} ${Errors}
    Delete "$DESKTOP\${PRODUCTNAME}.lnk"
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
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; subscriptions and settings go only when the user ticks "delete application data"; an update keeps them
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    ReadEnvStr $0 PROGRAMDATA
    RMDir /r "$0\Mistgate"
  ${EndIf}
!macroend

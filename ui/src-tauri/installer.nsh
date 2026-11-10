; What the installer does besides copying files: the background service, and cleaning up after itself.
; The service binary registers and removes itself (mistgate-clientd install / uninstall).

!macro NSIS_HOOK_PREINSTALL
  ; an update: stop and remove the running service so its file can be replaced (the VPN goes down with it)
  IfFileExists "$INSTDIR\mistgate-clientd.exe" 0 +2
    nsExec::ExecToLog '"$INSTDIR\mistgate-clientd.exe" uninstall'
!macroend

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToLog '"$INSTDIR\mistgate-clientd.exe" install'
  Pop $0
  StrCmp $0 "0" +2
    MessageBox MB_ICONEXCLAMATION|MB_OK "The Mistgate background service could not be started (code $0). Mistgate will not be able to connect until it runs." /SD IDOK
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

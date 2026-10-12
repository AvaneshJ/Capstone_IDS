; electron-builder NSIS hooks for SentinelAI (see "nsis.include" in package.json).

!macro customInit
  ; A running engine locks files in resources\backend during an upgrade.
  nsExec::Exec 'taskkill /F /T /IM sentinel-backend.exe'
  ; This stop is intended: drop the run marker so the next start doesn't report a tamper kill.
  ReadEnvStr $0 PROGRAMDATA
  Delete "$0\SentinelAI\engine_run.json"
!macroend

!macro customInstall
  ; Trust the files that were just installed: SHA-256 of models, policies and schema, signed with
  ; this machine's key in %PROGRAMDATA%\SentinelAI. Re-run on every install/upgrade so the
  ; manifest always matches the installed version.
  DetailPrint "Recording trusted fingerprints of SentinelAI's detection models..."
  nsExec::ExecToLog '"$INSTDIR\resources\backend\sentinel-backend.exe" integrity generate'
!macroend

!macro customUnInit
  nsExec::Exec 'taskkill /F /T /IM sentinel-backend.exe'
  ReadEnvStr $0 PROGRAMDATA
  Delete "$0\SentinelAI\engine_run.json"
!macroend

!macro customUnInstall
  ; Login task created by "Launch at login" when the app runs elevated. Incident history in
  ; %PROGRAMDATA%\SentinelAI is kept.
  nsExec::Exec 'schtasks /Delete /F /TN SentinelAI'
!macroend

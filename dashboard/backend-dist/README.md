# Bundled protection engine

The installer copies this folder into `resources/backend/`. When it contains
`sentinel-backend.exe` (the SOAR backend frozen with PyInstaller), the desktop app
starts that instead of looking for the repo's `.venv` Python. Without it, the app
runs the engine from the source checkout (`../soar/main.py`).

When freezing, include the WinDivert driver that ships inside `pydivert`
(`WinDivert64.dll` / `WinDivert64.sys`, LGPL) so live network monitoring works on PCs
without Npcap:

```
pyinstaller --name sentinel-backend --collect-data pydivert --collect-submodules scapy ... main.py
```

The installed app requests Administrator rights on launch (`requestedExecutionLevel`),
which the engine inherits. WinDivert capture and the credential-file sensor need it.

# Bundled protection engine

The installer copies this folder into `resources/backend/`. When it contains
`sentinel-backend.exe` (the SOAR backend frozen with PyInstaller), the desktop app
starts that instead of looking for the repo's `.venv` Python. Without it, the app
runs the engine from the source checkout (`../soar/main.py`).

Build everything from `dashboard/`:

```
npm run installer        # = npm run backend:build && npm run desktop:dist
```

- `backend:build` runs `packaging/build_backend.ps1` (recipe: `packaging/sentinel-backend.spec`)
  and stages the onedir build here, including the models, `schema.sql`, `policies.yaml` and
  the WinDivert driver from `pydivert` (LGPL) so capture works on PCs without Npcap.
- `desktop:dist` produces `release/SentinelAI Setup <version>.exe`.

The installed app requests Administrator rights (`requestedExecutionLevel`), which the engine
inherits. The installer runs `sentinel-backend.exe integrity generate` after copying files
(`electron/installer.nsh`), and the engine creates the manifest on first start if that step
was skipped. Runtime data (database, logs, reports, token, manifest) lives in
`%PROGRAMDATA%\SentinelAI` and is kept on uninstall.

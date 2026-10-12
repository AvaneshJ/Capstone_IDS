# SentinelAI Desktop

Windows desktop app (Electron + React) for SentinelAI. Shows network (NIDS) and host (HIDS) incidents from the SOAR
backend in plain language, with live alerts, Windows notifications and a system tray icon.

## Quick start

Requires the root `.venv` (see the root README). The desktop app starts the SOAR engine itself
(`.venv\Scripts\python.exe soar\main.py server` on `127.0.0.1:8000`) and stops it on quit. If an engine is already
running on that port, the app connects to it instead.

```powershell
cd dashboard
npm install
npm run desktop:dev              # Vite + Electron with hot reload
npm run desktop                  # production build in the desktop window
```

`npm` commands must be run from inside `dashboard/`. `npm run dev` still serves the UI in a browser at
`http://localhost:5173` (start the backend yourself with `cd soar; python main.py server`).

## Desktop app

- Frameless window with its own title bar, collapsible sidebar (`Ctrl + B`), Simple / Expert view.
- Closing the window keeps SentinelAI running in the system tray; right-click the tray icon to quit.
  Both this and "Start with Windows" can be changed in Settings.
- Engine logs: `%APPDATA%\SentinelAI\logs\engine.log`. If the engine stops, a banner offers "Start again".
- Environment overrides: `SENTINEL_API_PORT`, `SENTINEL_HOME` (repo root), `SENTINEL_PYTHON`.

### Building the installer

```powershell
npm run desktop:dist             # release\SentinelAI Setup 1.0.0.exe
```

The installer runs the engine from `SENTINEL_HOME` / the repo unless a frozen backend
(`sentinel-backend.exe`, e.g. built with PyInstaller) is placed in `backend-dist/` before building.

## Configuration (`.env.local`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `VITE_API_BASE` | `http://localhost:8000` | SOAR REST API base URL |
| `VITE_WS_URL` | derived from `VITE_API_BASE` | Live stream, `ws://…/ws/live-stream` |
| `VITE_USE_MOCKS` | `false` | `true` runs the UI with bundled mock data (`src/api/mocks/`) and fake live alerts, no backend needed |

Restart `npm run dev` after changing env values.

## Pages

| Route | Page | Data |
|-------|------|------|
| `/` | Home | Overall status, KPIs, recent alerts (`/api/metrics`, `/api/incidents`, `/api/host/incidents`) |
| `/activity` | Activity | Merged network + host alert feed with filters |
| `/activity/:source/:id` | Alert detail | Story view, risk gauge, actions taken, technical details (`/api/incidents/{id}` or host row) |
| `/blocked` | Blocked connections | Firewall rules, manual unblock (`/api/blocks`, `/api/blocks/unblock/{rule_id}`) |
| `/computer` | Computer protection | Host (HIDS) incidents |
| `/reports` | Reports | Generate + download PDF (`/api/reports/generate`) |
| `/health` | System health | Agent status, CPU / memory (`/api/status`) |
| `/learn` | Learn | Plain-language explanations of attack types |
| `/settings` | Settings | Preferences |
| `/demo` | Demo panel (Expert mode only) | Sends a sample flow or stealer event through the real pipeline |

## Live updates

`src/hooks/useLiveStream.ts` connects to `/ws/live-stream` and:

- shows the **Live / Reconnecting / Offline** status in the top bar,
- turns `THREAT_ALERT` events into toasts, bell notifications and (for serious threats) a Windows notification and
  sound that link to the matching incident (`incident_id`),
- refreshes cached queries on `NEW_INCIDENT` / `NEW_HOST_INCIDENT`,
- reconnects with backoff and falls back to polling while disconnected.

## Simple vs Expert view

- **Simple** (default): plain-English stories, no jargon.
- **Expert**: technical details open by default (readable field grid with probability bars, plus "Copy as JSON"),
  and the Demo panel is enabled.

## Test mode

The backend runs with dry-run firewall and host response by default (`/api/status` reports `test_mode: true`), so
the top bar shows a **Test mode** badge and actions read "Test mode: …" / "we would have …" instead of claiming
something was blocked or stopped.

## Tech stack

- Electron (`electron/main.cjs`, `electron/preload.cjs`), electron-builder (NSIS installer)
- React 19, TypeScript, Vite 8
- Tailwind CSS v4 (`@tailwindcss/vite`, no `tailwind.config.js` / PostCSS config); design tokens and glass
  component classes in `src/styles/index.css`
- TanStack Query, react-router v7
- Recharts, sonner (toasts), dayjs, lucide-react

## Scripts

| Command | Does |
|---------|------|
| `npm run desktop:dev` | Desktop app with hot reload |
| `npm run desktop` | Build, then open the desktop app |
| `npm run desktop:dist` | Build the Windows installer into `release/` |
| `npm run icons` | Regenerate `electron/assets/icon.png` and `tray.png` |
| `npm run dev` | Browser dev server with hot reload |
| `npm run build` | `tsc -b` type-check + production build to `dist/` |
| `npm run lint` | oxlint |
| `npm run preview` | Serve the production build |

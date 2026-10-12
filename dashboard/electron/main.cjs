const { app, BrowserWindow, ipcMain, Tray, Menu, Notification, shell, nativeImage, session } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const { spawn, execFile } = require('node:child_process');

const API_HOST = '127.0.0.1';
const API_PORT = Number(process.env.SENTINEL_API_PORT || 8000);
const API_BASE = `http://${API_HOST}:${API_PORT}`;
const DEV_URL = process.env.SENTINEL_DEV_URL || 'http://localhost:5173';
const isDev = process.argv.includes('--dev');
const startHidden = process.argv.includes('--hidden');

if (isDev) process.env.ELECTRON_DISABLE_SECURITY_WARNINGS = 'true';

const ICON = path.join(__dirname, 'assets', 'icon.png');
const TRAY_ICON = path.join(__dirname, 'assets', 'tray.png');

let mainWindow = null;
let tray = null;
let quitting = false;
let engineProc = null;
let engine = { status: 'starting', message: '', logPath: '' };

// ── Settings ───────────────────────────────────────────────────────────────

const DEFAULT_SETTINGS = { closeToTray: true, launchAtLogin: false, trayHintShown: false };
let settings = { ...DEFAULT_SETTINGS };

function settingsPath() {
  return path.join(app.getPath('userData'), 'settings.json');
}

function loadSettings() {
  try {
    settings = { ...DEFAULT_SETTINGS, ...JSON.parse(fs.readFileSync(settingsPath(), 'utf8')) };
  } catch {
    settings = { ...DEFAULT_SETTINGS };
  }
}

function saveSettings() {
  fs.mkdirSync(path.dirname(settingsPath()), { recursive: true });
  fs.writeFileSync(settingsPath(), JSON.stringify(settings, null, 2));
}

// ── Administrator rights ─────────────────────────────────────────────────
// Network capture without Npcap (WinDivert) and the saved-password file sensor both need an
// elevated engine. The installed app asks for admin through its manifest
// (requestedExecutionLevel); the engine inherits the elevation from this process.

let elevated = false;
const LOGIN_TASK = 'SentinelAI';

function checkElevated() {
  if (process.platform !== 'win32') return Promise.resolve(typeof process.getuid === 'function' && process.getuid() === 0);
  return new Promise((resolve) => execFile('net', ['session'], { windowsHide: true }, (err) => resolve(!err)));
}

function relaunchArgs() {
  const flags = process.argv.slice(1).filter((a) => a.startsWith('--') && a !== '--hidden');
  return app.isPackaged ? flags : [app.getAppPath(), ...flags];
}

function psQuote(s) {
  return `'${String(s).replace(/'/g, "''")}'`;
}

async function relaunchAsAdmin() {
  if (process.platform !== 'win32' || elevated) return { ok: elevated };
  // The elevated copy must start its own engine and pass the single-instance check.
  setEngine({ status: 'stopped', message: '' });
  await stopEngine();
  app.releaseSingleInstanceLock();

  const args = relaunchArgs();
  const argList = args.length ? ` -ArgumentList ${args.map(psQuote).join(',')}` : '';
  const command = `Start-Process -FilePath ${psQuote(process.execPath)}${argList} -Verb RunAs`;
  const ok = await new Promise((resolve) =>
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], { windowsHide: true }, (err) => resolve(!err)),
  );
  if (ok) {
    quitting = true;
    app.quit();
    return { ok: true };
  }
  // UAC prompt was declined: carry on without admin.
  app.requestSingleInstanceLock();
  startEngine();
  return { ok: false };
}

function applyLoginItem() {
  const args = app.isPackaged ? ['--hidden'] : [app.getAppPath(), '--hidden'];
  if (process.platform === 'win32' && elevated) {
    // Windows skips Run-key entries that need elevation, so an elevated app starts at login
    // through a scheduled task that runs with highest privileges.
    app.setLoginItemSettings({ openAtLogin: false });
    if (settings.launchAtLogin) {
      const target = [process.execPath, ...args].map((a) => `"${a}"`).join(' ');
      execFile('schtasks', ['/Create', '/F', '/TN', LOGIN_TASK, '/SC', 'ONLOGON', '/RL', 'HIGHEST', '/TR', target], { windowsHide: true }, () => {});
    } else {
      execFile('schtasks', ['/Delete', '/F', '/TN', LOGIN_TASK], { windowsHide: true }, () => {});
    }
    return;
  }
  app.setLoginItemSettings({ openAtLogin: settings.launchAtLogin, path: process.execPath, args });
}

function publicSettings() {
  return { closeToTray: settings.closeToTray, launchAtLogin: settings.launchAtLogin };
}

// ── Protection engine (SOAR FastAPI backend) ──────────────────────────────

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Same lookup order as config/security.py. The file is ACL-restricted to this user, SYSTEM and Administrators.
function readApiToken() {
  if (process.env.SENTINEL_API_TOKEN) return process.env.SENTINEL_API_TOKEN.trim();
  const dirs = process.env.SENTINEL_DATA_DIR
    ? [process.env.SENTINEL_DATA_DIR]
    : [process.env.PROGRAMDATA, process.env.LOCALAPPDATA].filter(Boolean).map((d) => path.join(d, 'SentinelAI'))
        .concat(path.join(app.getPath('home'), '.sentinelai'));
  for (const dir of dirs) {
    try {
      const token = fs.readFileSync(path.join(dir, 'api_token'), 'utf8').trim();
      if (token) return token;
    } catch {}
  }
  return '';
}

async function notifyEngineStopping() {
  try {
    await fetch(`${API_BASE}/api/engine/stopping`, {
      method: 'POST',
      headers: { 'X-SentinelAI-Token': readApiToken() },
      signal: AbortSignal.timeout(2000),
    });
  } catch {}
}

async function isEngineUp(timeoutMs = 1500) {
  try {
    const res = await fetch(`${API_BASE}/`, { signal: AbortSignal.timeout(timeoutMs) });
    return res.ok;
  } catch {
    return false;
  }
}

function resolveEngine() {
  const args = ['server', '--host', API_HOST, '--port', String(API_PORT)];

  // A frozen backend (e.g. PyInstaller) shipped inside the installer takes priority.
  if (app.isPackaged) {
    const exe = path.join(process.resourcesPath, 'backend', 'sentinel-backend.exe');
    if (fs.existsSync(exe)) return { command: exe, args, cwd: path.dirname(exe) };
  }

  const root = process.env.SENTINEL_HOME || path.resolve(__dirname, '..', '..');
  const soarDir = path.join(root, 'soar');
  if (!fs.existsSync(path.join(soarDir, 'main.py'))) return null;

  const venvPython = path.join(root, '.venv', 'Scripts', 'python.exe');
  const python = process.env.SENTINEL_PYTHON || (fs.existsSync(venvPython) ? venvPython : 'python');
  return { command: python, args: ['main.py', ...args], cwd: soarDir };
}

function setEngine(patch) {
  engine = { ...engine, lostContact: false, ...patch };
  mainWindow?.webContents.send('engine:state', engine);
  refreshTray();
}

async function startEngine() {
  if (engineProc) return engine;
  if (await isEngineUp()) {
    setEngine({ status: 'external', message: 'Connected to the running protection engine.' });
    return engine;
  }

  const spec = resolveEngine();
  if (!spec) {
    setEngine({ status: 'failed', message: "Couldn't find the protection engine files." });
    return engine;
  }

  setEngine({ status: 'starting', message: '' });
  const log = fs.createWriteStream(engine.logPath, { flags: 'a' });
  log.write(`\n=== ${new Date().toISOString()} ${spec.command} ${spec.args.join(' ')} (cwd ${spec.cwd})\n`);

  const proc = spawn(spec.command, spec.args, {
    cwd: spec.cwd,
    windowsHide: true,
    env: { ...process.env, PYTHONUNBUFFERED: '1', PYTHONIOENCODING: 'utf-8' },
  });
  engineProc = proc;
  proc.stdout.pipe(log, { end: false });
  proc.stderr.pipe(log, { end: false });
  proc.on('error', (err) => {
    log.write(`spawn error: ${err.message}\n`);
    if (engineProc === proc) engineProc = null;
    setEngine({ status: 'failed', message: `Couldn't start the protection engine (${err.message}).` });
  });
  proc.on('exit', (code) => {
    log.write(`exited with code ${code}\n`);
    if (engineProc === proc) engineProc = null;
    if (!quitting && engine.status !== 'stopped') {
      setEngine({ status: 'failed', message: `The protection engine stopped unexpectedly (code ${code}).` });
    }
  });

  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline && engineProc === proc) {
    if (await isEngineUp()) {
      setEngine({ status: 'running', message: '' });
      return engine;
    }
    await sleep(1000);
  }
  if (engineProc === proc && engine.status === 'starting') {
    setEngine({ status: 'failed', message: 'The protection engine took too long to start.' });
  }
  return engine;
}

function stopEngine() {
  const proc = engineProc;
  if (!proc) return Promise.resolve();
  engineProc = null;
  return new Promise((resolve) => {
    proc.once('exit', () => resolve());
    // Tell the engine this stop is intended so it isn't reported as a tamper kill on next start.
    notifyEngineStopping().finally(() => {
      if (process.platform === 'win32') {
        execFile('taskkill', ['/pid', String(proc.pid), '/T', '/F'], () => {});
      } else {
        proc.kill('SIGTERM');
      }
    });
    setTimeout(resolve, 5000);
  });
}

async function restartEngine() {
  setEngine({ status: 'stopped', message: '' });
  await stopEngine();
  return startEngine();
}

function watchEngine() {
  // A busy machine can delay a single health check, so only report a loss after several misses in a row.
  let misses = 0;
  setInterval(async () => {
    const watching = engine.status === 'running' || engine.status === 'external';
    const lostContact = engine.status === 'failed' && engine.lostContact;
    if (!watching && !lostContact) return;

    if (await isEngineUp(5000)) {
      misses = 0;
      if (lostContact) setEngine({ status: engineProc ? 'running' : 'external', message: '' });
      return;
    }
    misses += 1;
    if (watching && misses >= 3) {
      setEngine({ status: 'failed', message: 'Lost contact with the protection engine.', lostContact: true });
    }
  }, 15_000);
}

// ── Window ────────────────────────────────────────────────────────────────
// A window left in the tray is destroyed after UNLOAD_HIDDEN_AFTER_MS, which frees the renderer and
// its GPU memory (~150 MB). While there is no window, the main process listens for alerts itself.

const UNLOAD_HIDDEN_AFTER_MS = 2 * 60_000;
let unloadTimer = null;
let desktopNotifyEnabled = true;

function showWindow(route) {
  const target = typeof route === 'string' ? route : null;
  if (!mainWindow) return createWindow({ route: target });
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
  if (target) mainWindow.webContents.send('app:navigate', target);
}

function scheduleUnload() {
  clearTimeout(unloadTimer);
  unloadTimer = setTimeout(unloadWindow, UNLOAD_HIDDEN_AFTER_MS);
}

async function unloadWindow() {
  if (!mainWindow || mainWindow.isVisible() || quitting) return;
  try {
    const pref = await mainWindow.webContents.executeJavaScript("localStorage.getItem('sentinel_desktop_notify')");
    desktopNotifyEnabled = pref !== 'false';
  } catch {}
  if (!mainWindow || mainWindow.isVisible() || quitting) return;
  mainWindow.destroy();
  startAlertListener();
}

function isAppUrl(url) {
  return isDev ? url.startsWith(DEV_URL) : url.startsWith('file://');
}

function createWindow({ show = true, route = null } = {}) {
  clearTimeout(unloadTimer);
  stopAlertListener();
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    frame: false,
    backgroundColor: '#08080d',
    show: false,
    title: 'SentinelAI',
    icon: ICON,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
      backgroundThrottling: true,
      devTools: isDev,
    },
  });

  mainWindow.once('ready-to-show', () => {
    if (show) mainWindow.show();
  });
  mainWindow.on('show', () => clearTimeout(unloadTimer));
  mainWindow.on('hide', scheduleUnload);

  mainWindow.on('maximize', () => mainWindow.webContents.send('win:maximized', true));
  mainWindow.on('unmaximize', () => mainWindow.webContents.send('win:maximized', false));

  mainWindow.on('close', (e) => {
    if (quitting || !settings.closeToTray) return;
    e.preventDefault();
    mainWindow.hide();
    if (!settings.trayHintShown) {
      showNotification({
        title: 'SentinelAI is still protecting you',
        body: 'It keeps running in the system tray. Right-click the tray icon to quit.',
      });
      settings.trayHintShown = true;
      saveSettings();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });

  mainWindow.webContents.on('will-navigate', (e, url) => {
    if (isAppUrl(url)) return;
    e.preventDefault();
    if (/^https?:\/\//.test(url)) shell.openExternal(url);
  });

  // HashRouter: opening straight on the route avoids racing the renderer's navigate listener.
  if (isDev) mainWindow.loadURL(route ? `${DEV_URL}#${route}` : DEV_URL);
  else mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'), route ? { hash: route } : undefined);
}

// ── Alerts while the window is unloaded ──────────────────────────────────
// Mirrors the renderer: only HIGH / CRITICAL threats raise a desktop notification.

const THREAT_TITLES = {
  ddos: 'Flood attack',
  dos: 'Overload attack',
  botnet: 'Hijacked-device activity',
  sshbruteforce: 'Password-guessing attack (remote login)',
  ftpbruteforce: 'Password-guessing attack (file sharing)',
  bruteforce: 'Password-guessing attack',
  portscan: 'Someone checking for open doors',
  infiltration: 'Break-in attempt',
  webattack: 'Website attack',
  stealer: 'Password-stealing program',
  infostealer: 'Password-stealing program',
  ransomware: 'Ransomware (file-locking program)',
  malware: 'Harmful program',
};

let alertSocket = null;
let alertRetry = null;

function onBackgroundAlert(raw) {
  let msg;
  try {
    msg = JSON.parse(raw);
  } catch {
    return;
  }
  const alert = msg?.event_type === 'THREAT_ALERT' ? msg.data : null;
  const severity = String(alert?.severity || '').toUpperCase();
  if (!alert || (severity !== 'CRITICAL' && severity !== 'HIGH') || !desktopNotifyEnabled) return;
  const source = alert.source === 'HIDS' ? 'computer' : 'network';
  const key = String(alert.attack_type || '').toLowerCase().replace(/[\s_-]+/g, '');
  showNotification({
    title: THREAT_TITLES[key] || 'Suspicious activity',
    body: `${severity === 'CRITICAL' ? 'Critical' : 'High'} risk ${source === 'computer' ? 'on this computer' : 'from the network'}. Click to see what SentinelAI did.`,
    route: alert.incident_id ? `/activity/${source}/${alert.incident_id}` : '/activity',
    urgent: severity === 'CRITICAL',
  });
}

function startAlertListener() {
  if (alertSocket || mainWindow || quitting) return;
  const token = readApiToken();
  const url = `${API_BASE.replace(/^http/, 'ws')}/ws/live-stream${token ? `?token=${encodeURIComponent(token)}` : ''}`;
  let ws;
  try {
    ws = new WebSocket(url);
  } catch {
    scheduleAlertRetry();
    return;
  }
  alertSocket = ws;
  ws.onmessage = (e) => onBackgroundAlert(String(e.data));
  ws.onerror = () => ws.close();
  ws.onclose = () => {
    if (alertSocket !== ws) return;
    alertSocket = null;
    scheduleAlertRetry();
  };
}

function scheduleAlertRetry() {
  clearTimeout(alertRetry);
  if (mainWindow || quitting) return;
  alertRetry = setTimeout(startAlertListener, 15_000);
}

function stopAlertListener() {
  clearTimeout(alertRetry);
  const ws = alertSocket;
  alertSocket = null;
  ws?.close();
}

// ── Tray + notifications ─────────────────────────────────────────────────

const ENGINE_TRAY_LABEL = {
  starting: 'Protection: starting',
  running: 'Protection: on',
  external: 'Protection: on',
  stopped: 'Protection: off',
  failed: 'Protection: stopped (open to fix)',
};

function refreshTray() {
  if (!tray) return;
  tray.setToolTip(`SentinelAI · ${ENGINE_TRAY_LABEL[engine.status] ?? ''}`);
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: 'Open SentinelAI', click: showWindow },
      { type: 'separator' },
      { label: ENGINE_TRAY_LABEL[engine.status] ?? 'Protection', enabled: false },
      { label: 'Restart protection engine', click: () => restartEngine() },
      ...(process.platform === 'win32' && !elevated
        ? [{ label: 'Restart as administrator', click: () => relaunchAsAdmin() }]
        : []),
      { type: 'separator' },
      { label: 'Quit SentinelAI', click: () => { quitting = true; app.quit(); } },
    ])
  );
}

function createTray() {
  tray = new Tray(nativeImage.createFromPath(TRAY_ICON));
  tray.on('click', showWindow);
  refreshTray();
}

function showNotification({ title, body, route, urgent }) {
  if (!Notification.isSupported()) return;
  const n = new Notification({ title, body, icon: ICON, silent: true, urgency: urgent ? 'critical' : 'normal' });
  n.on('click', () => showWindow(route));
  n.show();
}

// ── IPC ───────────────────────────────────────────────────────────────────

function registerIpc() {
  ipcMain.on('win:minimize', () => mainWindow?.minimize());
  ipcMain.on('win:toggle-maximize', () => {
    if (!mainWindow) return;
    mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize();
  });
  ipcMain.on('win:close', () => mainWindow?.close());
  ipcMain.handle('win:is-maximized', () => mainWindow?.isMaximized() ?? false);

  ipcMain.handle('app:info', () => ({ version: app.getVersion(), platform: process.platform, apiBase: API_BASE, elevated }));
  ipcMain.handle('app:relaunch-admin', () => relaunchAsAdmin());
  ipcMain.handle('app:api-token', () => readApiToken());

  ipcMain.on('app:notify', (_e, payload) => {
    if (mainWindow?.isVisible() && mainWindow.isFocused()) return;
    showNotification(payload);
  });

  ipcMain.on('app:download', (_e, url) => {
    if (typeof url === 'string' && /^http:\/\/(127\.0\.0\.1|localhost):\d+\/api\/reports\/download\//.test(url)) {
      const u = new URL(url);
      u.searchParams.set('token', readApiToken());
      mainWindow?.webContents.downloadURL(u.toString());
    }
  });

  ipcMain.on('app:open-external', (_e, url) => {
    if (typeof url === 'string' && /^https:\/\//.test(url)) shell.openExternal(url);
  });

  ipcMain.handle('engine:get', () => engine);
  ipcMain.handle('engine:restart', () => restartEngine());

  ipcMain.handle('settings:get', () => publicSettings());
  ipcMain.handle('settings:set', (_e, patch) => {
    if (typeof patch?.closeToTray === 'boolean') settings.closeToTray = patch.closeToTray;
    if (typeof patch?.launchAtLogin === 'boolean') {
      settings.launchAtLogin = patch.launchAtLogin;
      applyLoginItem();
    }
    saveSettings();
    return publicSettings();
  });
}

function registerDownloads() {
  session.defaultSession.on('will-download', (_e, item) => {
    item.once('done', (_ev, state) => {
      if (state !== 'completed') return;
      const file = item.getSavePath();
      const n = new Notification({ title: 'Report saved', body: 'Click to show it in File Explorer.', icon: ICON, silent: true });
      n.on('click', () => shell.showItemInFolder(file));
      n.show();
    });
  });
}

// ── App lifecycle ────────────────────────────────────────────────────────

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', showWindow);

  app.whenReady().then(async () => {
    app.setAppUserModelId('com.sentinelai.desktop');
    loadSettings();
    elevated = await checkElevated();
    if (settings.launchAtLogin) applyLoginItem();

    const logDir = path.join(app.getPath('userData'), 'logs');
    fs.mkdirSync(logDir, { recursive: true });
    engine.logPath = path.join(logDir, 'engine.log');

    registerIpc();
    registerDownloads();
    createTray();
    // Started at login: no window until the user opens one from the tray.
    if (startHidden) startAlertListener();
    else createWindow();
    startEngine();
    watchEngine();
  });

  app.on('window-all-closed', () => {
    if (quitting || !settings.closeToTray) app.quit();
  });

  let cleanedUp = false;
  app.on('before-quit', (e) => {
    quitting = true;
    if (cleanedUp || !engineProc) return;
    e.preventDefault();
    cleanedUp = true;
    setEngine({ status: 'stopped', message: '' });
    stopEngine().finally(() => app.quit());
  });
}

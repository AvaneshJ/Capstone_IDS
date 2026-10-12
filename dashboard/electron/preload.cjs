const { contextBridge, ipcRenderer } = require('electron');

function subscribe(channel, cb) {
  const listener = (_e, value) => cb(value);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}

contextBridge.exposeInMainWorld('sentinel', {
  isDesktop: true,
  minimize: () => ipcRenderer.send('win:minimize'),
  toggleMaximize: () => ipcRenderer.send('win:toggle-maximize'),
  close: () => ipcRenderer.send('win:close'),
  isMaximized: () => ipcRenderer.invoke('win:is-maximized'),
  onMaximizedChange: (cb) => subscribe('win:maximized', cb),
  appInfo: () => ipcRenderer.invoke('app:info'),
  relaunchAsAdmin: () => ipcRenderer.invoke('app:relaunch-admin'),
  notify: (payload) => ipcRenderer.send('app:notify', payload),
  onNavigate: (cb) => subscribe('app:navigate', cb),
  download: (url) => ipcRenderer.send('app:download', url),
  openExternal: (url) => ipcRenderer.send('app:open-external', url),
  engineState: () => ipcRenderer.invoke('engine:get'),
  onEngineState: (cb) => subscribe('engine:state', cb),
  restartEngine: () => ipcRenderer.invoke('engine:restart'),
  getSettings: () => ipcRenderer.invoke('settings:get'),
  setSettings: (patch) => ipcRenderer.invoke('settings:set', patch),
  apiToken: () => ipcRenderer.invoke('app:api-token'),
});

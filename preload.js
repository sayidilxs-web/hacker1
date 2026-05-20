// preload.js - Expose full ipcRenderer capabilities securely
const { contextBridge, ipcRenderer } = require('electron');

// Expose ipcRenderer methods to renderer under window.ipcRenderer
contextBridge.exposeInMainWorld('ipcRenderer', {
    invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
    send: (channel, ...args) => ipcRenderer.send(channel, ...args),
    on: (channel, listener) => ipcRenderer.on(channel, listener),
    once: (channel, listener) => ipcRenderer.once(channel, listener),
    removeListener: (channel, listener) => ipcRenderer.removeListener(channel, listener),
    removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel)
});

// Also expose the same under electronAPI for backward compatibility
contextBridge.exposeInMainWorld('electronAPI', {
    startUnifiedScan: (target) => ipcRenderer.invoke('start-unified-scan', target),
    getTrafficLog: () => ipcRenderer.invoke('get-traffic-log'),
    clearTraffic: () => ipcRenderer.invoke('clear-traffic'),
    filterNoise: () => ipcRenderer.invoke('filter-noise'),
    exportData: (exportText) => ipcRenderer.invoke('export-data', exportText),
    onFeedUpdate: (callback) => {
        ipcRenderer.removeAllListeners('feed-update');
        ipcRenderer.on('feed-update', (event, data) => callback(data));
    }
});

// Log success
console.log('✅ Preload: Full ipcRenderer exposed under window.ipcRenderer');
console.log('Preload loaded. Full Node.js integration enabled.');

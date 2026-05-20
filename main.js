const { app, BrowserWindow, ipcMain, session } = require('electron');
const path = require('path');
const fs = require('fs');
const net = require('net');
const dns = require('dns').promises;
const axios = require('axios');
const whois = require('whois-json');
const jws = require('jws');

const DATA_DIR = path.join(__dirname, 'data');
const TRAFFIC_FILE = path.join(DATA_DIR, 'captured_traffic.json');
const SCAN_FILE = path.join(DATA_DIR, 'scan_results.json');
const EXPORT_FILE = path.join(DATA_DIR, 'export_for_deepseek.txt');
const DEFAULT_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443];
const SCAN_TIMEOUT = 2000;
const MAX_LOG_ENTRIES = 1000;

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

let mainWindow = null;
let captureLog = [];
let scanResults = {};

function loadLogs() {
    try { if (fs.existsSync(TRAFFIC_FILE)) captureLog = JSON.parse(fs.readFileSync(TRAFFIC_FILE)); } catch(e) {}
    try { if (fs.existsSync(SCAN_FILE)) scanResults = JSON.parse(fs.readFileSync(SCAN_FILE)); } catch(e) {}
}
loadLogs();

function saveTraffic() { fs.writeFileSync(TRAFFIC_FILE, JSON.stringify(captureLog.slice(-MAX_LOG_ENTRIES), null, 2)); }
function saveScanResults() { fs.writeFileSync(SCAN_FILE, JSON.stringify(scanResults, null, 2)); }

function setupSilentProxy() {
    const filter = { urls: ['<all_urls>'] };
    const ses = mainWindow.webContents.session;
    ses.webRequest.onBeforeRequest(filter, (details, callback) => {
        const entry = {
            id: Date.now(), timestamp: new Date().toISOString(), type: 'request',
            method: details.method, url: details.url, headers: details.requestHeaders,
            postData: details.uploadData ? details.uploadData[0].bytes.toString() : null
        };
        captureLog.push(entry);
        saveTraffic();
        mainWindow.webContents.send('feed-update', {
            module: 'Silent HTTP Proxy', details: `${details.method} ${details.url}`,
            request: JSON.stringify(details.requestHeaders, null, 2), response: ''
        });
        callback({ cancel: false });
    });
    ses.webRequest.onHeadersReceived(filter, (details, callback) => {
        const entry = {
            id: Date.now(), timestamp: new Date().toISOString(), type: 'response',
            url: details.url, statusCode: details.statusCode, headers: details.responseHeaders
        };
        captureLog.push(entry);
        saveTraffic();
        mainWindow.webContents.send('feed-update', {
            module: 'HTTP Response', details: `${details.statusCode} ${details.url}`,
            request: '', response: JSON.stringify(details.responseHeaders, null, 2)
        });
        callback({ cancel: false });
    });
}

async function scanPorts(host, ports = DEFAULT_PORTS) {
    const openPorts = [];
    for (const port of ports) {
        await new Promise(resolve => {
            const socket = new net.Socket();
            socket.setTimeout(SCAN_TIMEOUT);
            socket.once('connect', () => { openPorts.push({ port, service: getService(port) }); socket.destroy(); resolve(); });
            socket.once('timeout', () => { socket.destroy(); resolve(); });
            socket.once('error', () => { socket.destroy(); resolve(); });
            socket.connect(port, host);
        });
    }
    return openPorts;
}
function getService(port) {
    const services = {21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',80:'http',110:'pop3',143:'imap',443:'https',445:'smb',3306:'mysql',3389:'rdp',5432:'postgres',8080:'http-alt',8443:'https-alt'};
    return services[port] || 'unknown';
}

async function bruteSubdomains(domain) {
    const wordlist = ['www','mail','ftp','admin','blog','api','dev','test','vpn','remote','webmail','cpanel','ns1','ns2','smtp','pop','imap','cloud','docs','app','login','portal','shop','support','status','dashboard','cdn','static','media','video','images'];
    const found = [];
    for (const sub of wordlist) {
        try { await dns.lookup(`${sub}.${domain}`); found.push(`${sub}.${domain}`); } catch(e) {}
    }
    return found;
}

async function dirBuster(url) {
    const common = ['admin','backup','.git','.env','config','wp-admin','robots.txt','sitemap.xml','swagger'];
    const found = [];
    for (const d of common) {
        try { const res = await axios.head(`${url}/${d}`, { timeout: 2000 }); if (res.status < 400) found.push(d); } catch(e) {}
    }
    return found;
}

async function waybackUrls(domain) {
    try {
        const res = await axios.get(`https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&limit=50`);
        return res.data.slice(1).map(row => row[2]).filter(Boolean);
    } catch(e) { return []; }
}

async function leakScanner(url) {
    const paths = ['.git/HEAD', '.env', 'config.php', 'application.properties'];
    const leaks = [];
    for (const p of paths) {
        try { const res = await axios.get(`${url}/${p}`); if (res.status === 200) leaks.push(p); } catch(e) {}
    }
    return leaks;
}

async function getWhois(domain) {
    try { return await whois(domain); } catch(e) { return { error: e.message }; }
}

async function findBuckets(domain) {
    const names = [`${domain}`, `www-${domain}`, `static-${domain}`];
    const open = [];
    for (const name of names) {
        try { await axios.head(`http://${name}.s3.amazonaws.com`); open.push(name); } catch(e) {}
    }
    return open;
}

async function parseRobots(url) {
    try { const res = await axios.get(`${url}/robots.txt`); return res.data.split('\n').filter(l=>l.includes('Disallow')); } catch(e) { return []; }
}

function filterNoise(entries) {
    return entries.filter(e => !(e.type==='response' && e.statusCode===404) && !e.details?.includes('favicon'));
}

function compileForAI(target, logs, scan) {
    let output = `=== SHADOWRECON REPORT ===\nTarget: ${target}\nTimestamp: ${new Date().toISOString()}\n\n[PORT SCAN]\n${JSON.stringify(scan, null, 2)}\n\n[TRAFFIC LOG]\n`;
    logs.slice(-100).forEach(l => output += `${l.timestamp} ${l.method || 'response'} ${l.url || ''}\n`);
    return output;
}

ipcMain.handle('run-unified-scan', async (event, target) => {
    const [subdomains, ports, wayback, dirs, leaks, whoisData, buckets, robots] = await Promise.all([
        bruteSubdomains(target),
        scanPorts(target),
        waybackUrls(target),
        dirBuster(`https://${target}`),
        leakScanner(`https://${target}`),
        getWhois(target),
        findBuckets(target),
        parseRobots(`https://${target}`)
    ]);
    mainWindow.webContents.send('feed-update', { module: 'Port Scanner', details: `Open ports: ${ports.map(p=>p.port).join(', ')}`, request: '', response: JSON.stringify(ports) });
    mainWindow.webContents.send('feed-update', { module: 'Subdomain Bruter', details: `Found ${subdomains.length} subdomains`, request: '', response: subdomains.join('\n') });
    mainWindow.webContents.send('feed-update', { module: 'Wayback Crawler', details: `Fetched ${wayback.length} historic URLs`, request: '', response: wayback.slice(0,10).join('\n') });
    mainWindow.webContents.send('feed-update', { module: 'Directory Buster', details: `Found ${dirs.length} directories`, request: '', response: dirs.join('\n') });
    mainWindow.webContents.send('feed-update', { module: 'Leak Scanner', details: `Leaks: ${leaks.join(', ')}`, request: '', response: leaks.join('\n') });
    mainWindow.webContents.send('feed-update', { module: 'Whois Info', details: `Registrar: ${whoisData.registrar || 'N/A'}`, request: '', response: JSON.stringify(whoisData, null, 2) });
    mainWindow.webContents.send('feed-update', { module: 'Cloud Buckets', details: `Open buckets: ${buckets.join(', ')}`, request: '', response: buckets.join('\n') });
    mainWindow.webContents.send('feed-update', { module: 'Robots.txt', details: `Disallowed: ${robots.length}`, request: '', response: robots.join('\n') });
    return { status: 'completed' };
});

ipcMain.handle('get-traffic-log', () => captureLog);
ipcMain.handle('clear-traffic', () => { captureLog = []; saveTraffic(); return true; });
ipcMain.handle('filter-noise', () => {
    const before = captureLog.length;
    captureLog = filterNoise(captureLog);
    saveTraffic();
    return { removed: before - captureLog.length };
});
ipcMain.handle('export-for-ai', (event, target) => {
    const report = compileForAI(target, captureLog, scanResults);
    fs.writeFileSync(EXPORT_FILE, report);
    return EXPORT_FILE;
});

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400, height: 900,
        webPreferences: { nodeIntegration: true, contextIsolation: false, preload: path.join(__dirname, 'preload.js') },
        backgroundColor: '#03050b', titleBarStyle: 'hidden', frame: false
    });
    mainWindow.loadFile('index.html');
    mainWindow.on('closed', () => mainWindow = null);
    setupSilentProxy();
}

app.whenReady().then(() => { createWindow(); });
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

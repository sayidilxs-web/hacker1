// logger.js
const fs = require('fs');
const path = require('path');
const logFile = path.join(__dirname, 'data', 'app.log');
if (!fs.existsSync(path.dirname(logFile))) fs.mkdirSync(path.dirname(logFile), { recursive: true });
function write(level, msg) {
    const line = `[${new Date().toISOString()}] [${level}] ${msg}\n`;
    console.log(line.trim());
    fs.appendFileSync(logFile, line);
}
module.exports = { info: (m)=>write('INFO',m), warn: (m)=>write('WARN',m), error: (m)=>write('ERROR',m) };

// config.js
const path = require('path');
module.exports = {
    DATA_DIR: path.join(__dirname, 'data'),
    TRAFFIC_FILE: 'captured_traffic.json',
    SCAN_FILE: 'scan_results.json',
    EXPORT_FILE: 'export_for_deepseek.txt',
    DEFAULT_PORTS: [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443],
    SCAN_TIMEOUT: 2000,
    MAX_LOG_ENTRIES: 1000
};

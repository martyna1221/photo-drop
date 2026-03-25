const https = require("https");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { execSync } = require("child_process");
const express = require("express");
const multer = require("multer");
const selfsigned = require("selfsigned");
const qrcode = require("qrcode-terminal");

// ---------- Config ----------

function loadConfig() {
  const configPath = path.join(__dirname, "config.json");
  try {
    return JSON.parse(fs.readFileSync(configPath, "utf8"));
  } catch {
    return {};
  }
}

const config = loadConfig();

const PORT = 3333;
const CERTS_DIR = path.join(__dirname, "certs");
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB

const UPLOADS_DIR = config.uploadsDir
  ? path.resolve(__dirname, config.uploadsDir)
  : path.join(__dirname, "uploads");

// ---------- TLS cert ----------

function getCert() {
  const certPath = path.join(CERTS_DIR, "cert.pem");
  const keyPath = path.join(CERTS_DIR, "key.pem");

  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    return {
      cert: fs.readFileSync(certPath),
      key: fs.readFileSync(keyPath),
    };
  }

  fs.mkdirSync(CERTS_DIR, { recursive: true });

  const attrs = [{ name: "commonName", value: "photo-drop" }];
  const pems = selfsigned.generate(attrs, {
    days: 365,
    keySize: 2048,
    algorithm: "sha256",
  });

  fs.writeFileSync(certPath, pems.cert);
  fs.writeFileSync(keyPath, pems.private);

  return { cert: pems.cert, key: pems.private };
}

// ---------- Local IP ----------

function getLocalIP() {
  const interfaces = os.networkInterfaces();
  const candidates = [];

  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === "IPv4" && !iface.internal) {
        const isWifi = /wi-?fi|wireless/i.test(name);
        const isVirtual =
          /vEthernet|WSL|Hyper-V|VirtualBox|Docker|VMware/i.test(name);
        const isLinkLocal = iface.address.startsWith("169.254.");
        candidates.push({ address: iface.address, isWifi, isVirtual, isLinkLocal });
      }
    }
  }

  const pick =
    candidates.find((c) => c.isWifi && !c.isLinkLocal) ||
    candidates.find((c) => !c.isVirtual && !c.isLinkLocal) ||
    candidates.find((c) => !c.isLinkLocal) ||
    candidates[0];

  return pick ? pick.address : "127.0.0.1";
}

// ---------- PIN ----------

const PIN = String(Math.floor(1000 + Math.random() * 9000));
const SESSION_SECRET = crypto.randomBytes(32).toString("hex");

function makeSessionToken() {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(PIN)
    .digest("hex");
}

function isAuthed(req) {
  const cookie = req.headers.cookie || "";
  const match = cookie.match(/photo_drop_session=([^;]+)/);
  return match && match[1] === makeSessionToken();
}

// ---------- Multer ----------

fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const now = new Date();
    const ts = now
      .toISOString()
      .replace(/[-:]/g, "")
      .replace("T", "_")
      .slice(0, 15);
    const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, `${ts}_${safe}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
});

// ---------- Express ----------

const app = express();
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => {
  if (isAuthed(req)) return res.redirect("/upload");
  res.send(pinPage());
});

app.post("/auth", (req, res) => {
  if (req.body.pin === PIN) {
    res.setHeader(
      "Set-Cookie",
      `photo_drop_session=${makeSessionToken()}; Path=/; HttpOnly; Secure; SameSite=Strict`
    );
    return res.redirect("/upload");
  }
  res.send(pinPage("Wrong PIN. Try again."));
});

app.get("/upload", (req, res) => {
  if (!isAuthed(req)) return res.redirect("/");
  res.send(uploadPage());
});

app.post("/upload", (req, res) => {
  if (!isAuthed(req)) return res.status(401).json({ error: "Unauthorized" });

  upload.array("photos", 20)(req, res, (err) => {
    if (err) {
      const msg =
        err.code === "LIMIT_FILE_SIZE"
          ? "File too large (max 50MB)"
          : err.message;
      return res.status(400).json({ error: msg });
    }
    const files = (req.files || []).map((f) => f.filename);
    console.log(`Received ${files.length} file(s): ${files.join(", ")}`);
    res.json({ ok: true, files });
  });
});

// ---------- Firewall ----------

const FW_RULE_NAME = "photo-drop (port " + PORT + ")";

function ensureFirewallRule() {
  if (process.platform !== "win32") return true;
  try {
    // Disable any Node.js Block rules on Private that would override our Allow
    execSync(
      'netsh advfirewall firewall set rule name="Node.js JavaScript Runtime" dir=in profile=private new enable=no',
      { stdio: "ignore" }
    );
    execSync(
      `netsh advfirewall firewall add rule name="${FW_RULE_NAME}" dir=in action=allow protocol=TCP localport=${PORT}`,
      { stdio: "ignore" }
    );
    return true;
  } catch {
    return false;
  }
}

function removeFirewallRule() {
  if (process.platform !== "win32") return;
  try {
    execSync(
      `netsh advfirewall firewall delete rule name="${FW_RULE_NAME}"`,
      { stdio: "ignore" }
    );
  } catch {
    // best-effort cleanup
  }
}

// ---------- Start ----------

const tlsOpts = getCert();
const server = https.createServer(tlsOpts, app);
const ip = getLocalIP();
const url = `https://${ip}:${PORT}`;

const fwOk = ensureFirewallRule();

server.listen(PORT, "0.0.0.0", () => {
  console.log("");
  console.log("  photo-drop is running");
  console.log(`  URL:  ${url}`);
  console.log(`  PIN:  ${PIN}`);
  console.log("");

  if (!fwOk) {
    console.log("  \x1b[33mWARNING: Could not configure firewall (need admin).\x1b[0m");
    console.log("  If your iPhone can't connect, run these once in an elevated terminal:");
    console.log("");
    console.log('    netsh advfirewall firewall set rule name="Node.js JavaScript Runtime" dir=in profile=private new enable=no');
    console.log(`    netsh advfirewall firewall add rule name="${FW_RULE_NAME}" dir=in action=allow protocol=TCP localport=${PORT}`);
    console.log("");
  }

  console.log("  Scan this QR code with your iPhone camera:");
  console.log("");
  qrcode.generate(url, { small: true }, (code) => {
    console.log(
      code
        .split("\n")
        .map((l) => "  " + l)
        .join("\n")
    );
    console.log("");
    console.log("  Uploads land in: " + UPLOADS_DIR);
    console.log("  Press Ctrl+C to stop");
    console.log("");
  });
});

process.on("SIGINT", () => {
  console.log("\n  Shutting down...");
  removeFirewallRule();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000);
});

// ---------- HTML pages ----------

const CHROME_GRADIENT = '<linearGradient id="cg" x1="0" y1="0" x2="180" y2="0" gradientUnits="userSpaceOnUse">'
  + '<stop offset="0%" stop-color="#333"/><stop offset="35%" stop-color="#888"/>'
  + '<stop offset="50%" stop-color="#ccc"/><stop offset="65%" stop-color="#888"/>'
  + '<stop offset="100%" stop-color="#333"/></linearGradient>';

const SIGIL_SVG = '<svg class="sigil" viewBox="0 0 180 20" fill="none">'
  + '<defs>' + CHROME_GRADIENT + '</defs>'
  + '<line x1="0" y1="10" x2="55" y2="10" stroke="url(#cg)" stroke-width="0.5"/>'
  + '<path d="M55,10 L65,4 L72,10 L65,16 Z" stroke="url(#cg)" stroke-width="0.75" fill="none"/>'
  + '<path d="M78,10 L90,2 L102,10 L90,18 Z" stroke="url(#cg)" stroke-width="1" fill="none"/>'
  + '<path d="M84,10 L90,5 L96,10 L90,15 Z" fill="url(#cg)"/>'
  + '<path d="M108,10 L115,4 L125,10 L115,16 Z" stroke="url(#cg)" stroke-width="0.75" fill="none"/>'
  + '<line x1="125" y1="10" x2="180" y2="10" stroke="url(#cg)" stroke-width="0.5"/>'
  + '</svg>';

const SHARED_HEAD = `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>photo-drop</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Michroma&display=swap" rel="stylesheet">`;

const SHARED_STYLES = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', system-ui, sans-serif;
    background: #050505;
    color: #b0b0b0;
    min-height: 100dvh;
    -webkit-text-size-adjust: 100%;
    position: relative;
  }
  body::after {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,255,255,0.018) 2px, rgba(255,255,255,0.018) 4px);
    pointer-events: none;
    z-index: 10000;
  }
  h1 {
    font-family: 'Michroma', sans-serif;
    font-size: 24px;
    font-weight: 400;
    letter-spacing: 6px;
    text-transform: uppercase;
    background: linear-gradient(90deg, #555, #aaa, #fff, #aaa, #555);
    background-size: 200% auto;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    animation: shimmer 4s linear infinite;
  }
  @keyframes shimmer {
    0% { background-position: -200% center; }
    100% { background-position: 200% center; }
  }
  .sigil { display: block; margin: 16px auto 20px; width: 180px; height: 20px; }
  .corner { position: absolute; width: 16px; height: 16px; }
  .corner--tl { top: -1px; left: -1px; border-top: 2px solid #666; border-left: 2px solid #666; }
  .corner--tr { top: -1px; right: -1px; border-top: 2px solid #666; border-right: 2px solid #666; }
  .corner--bl { bottom: -1px; left: -1px; border-bottom: 2px solid #666; border-left: 2px solid #666; }
  .corner--br { bottom: -1px; right: -1px; border-bottom: 2px solid #666; border-right: 2px solid #666; }
`;

function pinPage(error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
${SHARED_HEAD}
<style>
  ${SHARED_STYLES}
  body {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }
  .card {
    width: 100%;
    max-width: 360px;
    text-align: center;
    position: relative;
    padding: 48px 36px;
    border: 1px solid #2a2a2a;
    background: #080808;
  }
  .sub {
    font-size: 11px;
    color: #555;
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-bottom: 28px;
  }
  .error {
    background: rgba(255,0,0,0.06);
    color: #cc3333;
    border: 1px solid #441111;
    padding: 10px 14px;
    font-size: 11px;
    margin-bottom: 20px;
    letter-spacing: 2px;
    text-transform: uppercase;
  }
  form { display: flex; flex-direction: column; gap: 14px; }
  input[type="text"] {
    width: 100%;
    padding: 16px;
    font-family: 'Michroma', sans-serif;
    font-size: 26px;
    font-weight: 700;
    text-align: center;
    letter-spacing: 14px;
    background: #0a0a0a;
    border: 1px solid #333;
    color: #e0e0e0;
    outline: none;
    -webkit-appearance: none;
    transition: border-color 0.3s, box-shadow 0.3s;
  }
  input[type="text"]:focus {
    border-color: #777;
    box-shadow: 0 0 15px rgba(180,180,180,0.1), inset 0 0 10px rgba(180,180,180,0.03);
  }
  input[type="text"]::placeholder { color: #222; }
  button {
    padding: 16px;
    font-family: 'Michroma', sans-serif;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 5px;
    text-transform: uppercase;
    background: linear-gradient(135deg, #222, #555, #777, #555, #222);
    color: #ddd;
    border: 1px solid #444;
    cursor: pointer;
    -webkit-appearance: none;
    transition: box-shadow 0.3s;
  }
  button:active {
    box-shadow: 0 0 20px rgba(200,200,200,0.15);
    border-color: #666;
  }
</style>
</head>
<body>
<div class="card">
  <span class="corner corner--tl"></span>
  <span class="corner corner--tr"></span>
  <span class="corner corner--bl"></span>
  <span class="corner corner--br"></span>
  <h1>photo-drop</h1>
  ${SIGIL_SVG}
  <p class="sub">Enter terminal PIN</p>
  ${error ? '<div class="error">' + error + '</div>' : ""}
  <form method="POST" action="/auth">
    <input type="text" name="pin" inputmode="numeric" pattern="[0-9]*"
           maxlength="4" autocomplete="off" autofocus placeholder="----">
    <button type="submit">Unlock</button>
  </form>
</div>
</body>
</html>`;
}

function uploadPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
${SHARED_HEAD}
<style>
  ${SHARED_STYLES}
  body {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 24px;
    padding-top: max(24px, env(safe-area-inset-top));
  }
  .wrap {
    width: 100%;
    max-width: 400px;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }
  h1 { text-align: center; padding-top: 12px; }

  .drop {
    border: 1px dashed #444;
    padding: 44px 24px;
    text-align: center;
    cursor: pointer;
    transition: border-color 0.3s, box-shadow 0.3s;
    position: relative;
  }
  .drop.active {
    border-color: #888;
    box-shadow: 0 0 20px rgba(180,180,180,0.08);
  }
  .drop-icon {
    font-family: 'Michroma', sans-serif;
    font-size: 36px;
    font-weight: 400;
    color: #444;
    margin-bottom: 10px;
    display: block;
  }
  .drop-label {
    font-size: 13px;
    color: #777;
    letter-spacing: 2px;
    text-transform: uppercase;
  }
  .drop-hint {
    font-size: 11px;
    color: #444;
    margin-top: 6px;
    letter-spacing: 1px;
  }
  .drop input {
    position: absolute;
    inset: 0;
    opacity: 0;
    cursor: pointer;
  }

  .files { display: flex; flex-direction: column; gap: 6px; }
  .file-item {
    display: flex;
    align-items: center;
    gap: 10px;
    background: #0c0c0c;
    border: 1px solid #222;
    padding: 8px 12px;
    font-size: 12px;
  }
  .file-thumb {
    width: 36px;
    height: 36px;
    object-fit: cover;
    background: #1a1a1a;
    flex-shrink: 0;
    border: 1px solid #333;
  }
  .file-name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: #999;
  }
  .file-size { color: #555; flex-shrink: 0; font-size: 11px; }
  .file-remove {
    background: none;
    border: none;
    color: #555;
    font-size: 16px;
    cursor: pointer;
    padding: 4px;
    line-height: 1;
    font-family: inherit;
  }
  .file-remove:active { color: #cc3333; }

  .upload-btn {
    padding: 16px;
    font-family: 'Michroma', sans-serif;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 5px;
    text-transform: uppercase;
    background: linear-gradient(135deg, #222, #555, #777, #555, #222);
    color: #ddd;
    border: 1px solid #444;
    cursor: pointer;
    -webkit-appearance: none;
    transition: box-shadow 0.3s, opacity 0.3s;
  }
  .upload-btn:disabled { opacity: 0.3; cursor: default; }
  .upload-btn:active:not(:disabled) {
    box-shadow: 0 0 20px rgba(200,200,200,0.15);
    border-color: #666;
  }

  .progress-wrap { display: none; flex-direction: column; gap: 8px; }
  .progress-wrap.show { display: flex; }
  .progress-bar-outer {
    height: 4px;
    background: #111;
    border: 1px solid #222;
    overflow: hidden;
  }
  .progress-bar {
    height: 100%;
    background: linear-gradient(90deg, #444, #999, #ccc, #999, #444);
    background-size: 200% auto;
    animation: shimmer 2s linear infinite;
    width: 0%;
    transition: width 0.2s;
  }
  .progress-text {
    font-size: 11px;
    color: #666;
    text-align: center;
    letter-spacing: 2px;
  }

  .status {
    text-align: center;
    padding: 14px;
    font-size: 12px;
    letter-spacing: 2px;
    text-transform: uppercase;
    display: none;
  }
  .status.success {
    display: block;
    background: rgba(0,180,0,0.06);
    color: #44aa44;
    border: 1px solid #1a3a1a;
  }
  .status.error {
    display: block;
    background: rgba(255,0,0,0.06);
    color: #cc3333;
    border: 1px solid #441111;
  }
</style>
</head>
<body>
<div class="wrap">
  <h1>photo-drop</h1>
  ${SIGIL_SVG}

  <div class="drop" id="dropZone">
    <span class="drop-icon">+</span>
    <div class="drop-label">Select photos</div>
    <div class="drop-hint">tap to browse</div>
    <input type="file" id="fileInput" accept="image/*" multiple>
  </div>

  <div class="files" id="fileList"></div>

  <button class="upload-btn" id="uploadBtn" disabled>Transmit</button>

  <div class="progress-wrap" id="progressWrap">
    <div class="progress-bar-outer">
      <div class="progress-bar" id="progressBar"></div>
    </div>
    <div class="progress-text" id="progressText">Transmitting...</div>
  </div>

  <div class="status" id="status"></div>
</div>

<script>
(function() {
  var fileInput = document.getElementById("fileInput");
  var dropZone = document.getElementById("dropZone");
  var fileList = document.getElementById("fileList");
  var uploadBtn = document.getElementById("uploadBtn");
  var progressWrap = document.getElementById("progressWrap");
  var progressBar = document.getElementById("progressBar");
  var progressText = document.getElementById("progressText");
  var statusEl = document.getElementById("status");

  var selectedFiles = [];

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / 1048576).toFixed(1) + " MB";
  }

  function renderFiles() {
    fileList.innerHTML = "";
    selectedFiles.forEach(function(file, i) {
      var item = document.createElement("div");
      item.className = "file-item";

      var thumb = document.createElement("img");
      thumb.className = "file-thumb";
      thumb.src = URL.createObjectURL(file);

      var name = document.createElement("div");
      name.className = "file-name";
      name.textContent = file.name;

      var size = document.createElement("div");
      size.className = "file-size";
      size.textContent = formatSize(file.size);

      var remove = document.createElement("button");
      remove.className = "file-remove";
      remove.innerHTML = "&#10005;";
      remove.onclick = function(e) {
        e.stopPropagation();
        selectedFiles.splice(i, 1);
        renderFiles();
      };

      item.append(thumb, name, size, remove);
      fileList.appendChild(item);
    });
    uploadBtn.disabled = selectedFiles.length === 0;
  }

  fileInput.addEventListener("change", function() {
    selectedFiles = selectedFiles.concat(Array.from(this.files));
    renderFiles();
    this.value = "";
  });

  uploadBtn.addEventListener("click", function() {
    if (selectedFiles.length === 0) return;

    var formData = new FormData();
    selectedFiles.forEach(function(f) { formData.append("photos", f); });

    var xhr = new XMLHttpRequest();

    uploadBtn.disabled = true;
    progressWrap.classList.add("show");
    statusEl.className = "status";
    statusEl.style.display = "none";

    xhr.upload.addEventListener("progress", function(e) {
      if (e.lengthComputable) {
        var pct = Math.round((e.loaded / e.total) * 100);
        progressBar.style.width = pct + "%";
        progressText.textContent = pct + "%";
      }
    });

    xhr.addEventListener("load", function() {
      progressWrap.classList.remove("show");
      progressBar.style.width = "0%";

      if (xhr.status === 200) {
        var resp = JSON.parse(xhr.responseText);
        statusEl.className = "status success";
        statusEl.textContent = resp.files.length + " file(s) transmitted";
        statusEl.style.display = "block";
        selectedFiles = [];
        renderFiles();
      } else {
        var resp = JSON.parse(xhr.responseText);
        statusEl.className = "status error";
        statusEl.textContent = resp.error || "Transmission failed";
        statusEl.style.display = "block";
        uploadBtn.disabled = false;
      }
    });

    xhr.addEventListener("error", function() {
      progressWrap.classList.remove("show");
      statusEl.className = "status error";
      statusEl.textContent = "Network error — check connection";
      statusEl.style.display = "block";
      uploadBtn.disabled = false;
    });

    xhr.open("POST", "/upload");
    xhr.send(formData);
  });
})();
</script>
</body>
</html>`;
}

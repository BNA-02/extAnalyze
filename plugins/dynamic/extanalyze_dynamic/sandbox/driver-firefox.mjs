// Firefox variant of the observation driver. Playwright cannot load Firefox extensions, so this
// drives Firefox through geckodriver (WebDriver classic over HTTP, no npm dependencies) and
// installs the extension as a temporary add-on.
//
// Network observation: Firefox is pointed at a recording proxy inside this process. The proxy
// terminates TLS with one self-signed certificate (geckodriver's acceptInsecureCerts disables
// certificate checks browser-wide), serves the canary pages for the impersonated sites, records
// every other request (including the extension's own background requests) and answers 200.
import { spawn } from "node:child_process";
import http from "node:http";
import tls from "node:tls";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  ALLOW_NETWORK, DOMAINS, EXT, LOCAL_HOSTS, SECONDS, canaries, cookieHeader, emit, fail, newResult, note, page,
  recordRaw,
} from "./shared.mjs";

const BROWSER_PATH = process.env.BROWSER_PATH;
const GECKODRIVER = process.env.GECKODRIVER || "/opt/geckodriver";
const LIBS = process.env.BROWSER_LIBS || "";
const PROXY_PORT = 8888;
const DRIVER_PORT = 4444;
const MAX_BODY = 1024 * 1024;
// Firefox's own housekeeping traffic: not attributable to the extension, so not reported
const FIREFOX_INTERNAL = new Set([
  "firefox.settings.services.mozilla.com", "content-signature-2.cdn.mozilla.net", "push.services.mozilla.com",
  "detectportal.firefox.com", "tracking-protection.cdn.mozilla.net", "location.services.mozilla.com",
  "normandy.cdn.mozilla.net", "incoming.telemetry.mozilla.org", "aus5.mozilla.org", "safebrowsing.googleapis.com",
  "firefox-settings-attachments.cdn.mozilla.net", "ciscobinary.openh264.org", "snippets.cdn.mozilla.net",
]);

// ── recording / serving proxy ─────────────────────────────────────────────────────────────────
function handle(req, res, scheme) {
  const chunks = [];
  let size = 0;
  req.on("data", (c) => { size += c.length; if (size <= MAX_BODY) chunks.push(c); });
  req.on("end", () => {
    const connectHost = req.socket.connectHost; // set for CONNECT tunnels
    let url;
    try {
      url = connectHost ? new URL(req.url, `${scheme}://${connectHost}`) : new URL(req.url);
    } catch { res.writeHead(400).end(); return; }
    const body = Buffer.concat(chunks).toString("latin1");
    if (LOCAL_HOSTS.has(url.hostname)) {
      if (req.method === "POST") { res.writeHead(204).end(); return; }
      res.writeHead(200, { "content-type": "text/html", "set-cookie": [cookieHeader()] });
      res.end(page(url.hostname));
      return;
    }
    const origin = req.headers.origin || "";
    if (FIREFOX_INTERNAL.has(url.hostname) && !origin) { res.writeHead(200).end("{}"); return; }
    // Best effort: requests from the extension's own pages carry a moz-extension Origin, or neither
    // Origin nor Referer; page and content-script requests carry the page's origin or referer.
    const fromBackground = origin.startsWith("moz-extension://") || (!origin && !req.headers.referer);
    recordRaw({
      url: url.href, method: req.method, postData: body, headers: req.headers, resourceType: "other",
      source: fromBackground ? "background_page" : "page",
    });
    res.writeHead(200, { "content-type": "application/json", "access-control-allow-origin": "*" });
    res.end("{}");
  });
}

function startProxy() {
  const secureContext = tls.createSecureContext({
    key: fs.readFileSync("/opt/sandbox/key.pem"), cert: fs.readFileSync("/opt/sandbox/cert.pem"),
  });
  const mitm = http.createServer((req, res) => handle(req, res, "https"));
  mitm.on("clientError", (_e, sock) => sock.destroy());
  const proxy = http.createServer((req, res) => handle(req, res, "http"));
  proxy.on("connect", (req, clientSocket, head) => {
    clientSocket.on("error", () => {});
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    const t = new tls.TLSSocket(clientSocket, { isServer: true, secureContext });
    t.connectHost = req.url.replace(/:443$/, "");
    t.on("error", () => {});
    if (head?.length) t.unshift(head);
    mitm.emit("connection", t);
  });
  proxy.on("clientError", (_e, sock) => sock.destroy());
  proxy.listen(PROXY_PORT, "127.0.0.1");
}

// ── WebDriver (classic) client ────────────────────────────────────────────────────────────────
const base = `http://127.0.0.1:${DRIVER_PORT}`;
async function wd(method, p, body) {
  const r = await fetch(base + p, {
    method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30000),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${method} ${p}: ${j.value?.message || r.status}`);
  return j.value;
}

async function startGeckodriver() {
  const child = spawn(GECKODRIVER, ["--port", String(DRIVER_PORT), "--host", "127.0.0.1"], {
    env: { ...process.env, LD_LIBRARY_PATH: LIBS, MOZ_HEADLESS: "1", HOME: os.tmpdir() },
    stdio: ["ignore", "ignore", "ignore"],
  });
  for (let i = 0; i < 40; i++) {
    try { if ((await fetch(base + "/status")).ok) return child; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  child.kill();
  throw new Error("geckodriver did not start");
}

async function interact(session, host) {
  const s = `/session/${session}`;
  const type = async (css, text) => {
    const el = (await wd("POST", `${s}/element`, { using: "css selector", value: css }))["element-6066-11e4-a52e-4f735466cecf"];
    await wd("POST", `${s}/element/${el}/value`, { text });
    return el;
  };
  try {
    await wd("POST", `${s}/url`, { url: `https://${host}/` });
    await type("#email", canaries.email);
    await type("#password", canaries.password);
    await type("#cc", canaries.card);
    await type("#q", canaries.search);
    const btn = (await wd("POST", `${s}/element`, { using: "css selector", value: "#submit" }))["element-6066-11e4-a52e-4f735466cecf"];
    await wd("POST", `${s}/element/${btn}/click`, {});
  } catch (e) {
    note(`interaction failed on ${host}: ${e.message}`);
  }
}

async function main() {
  const started = Date.now();
  const result = newResult(BROWSER_PATH ? path.basename(path.dirname(BROWSER_PATH)) : "firefox");
  const done = () => emit(result, started);
  const deadline = setTimeout(() => { note("overall deadline reached"); done(); process.exit(0); }, SECONDS * 1000 + 20000);

  let manifest = {};
  try { manifest = JSON.parse(fs.readFileSync(path.join(EXT, "manifest.json"), "utf8")); } catch { /* reported below */ }

  startProxy();
  await startGeckodriver();
  if (!ALLOW_NETWORK) note("sandbox network is disabled; external requests are answered locally by the recording proxy");

  const session = (await wd("POST", "/session", {
    capabilities: { alwaysMatch: {
      browserName: "firefox", acceptInsecureCerts: true,
      proxy: { proxyType: "manual", httpProxy: `127.0.0.1:${PROXY_PORT}`, sslProxy: `127.0.0.1:${PROXY_PORT}`, noProxy: [] },
      "moz:firefoxOptions": {
        binary: BROWSER_PATH, args: ["-headless"],
        prefs: {
          "network.proxy.allow_hijacking_localhost": true,
          "extensions.webextensions.restrictedDomains": "",
          "browser.shell.checkDefaultBrowser": false,
          "datareporting.policy.dataSubmissionEnabled": false,
          "app.update.auto": false, "app.update.enabled": false,
          "extensions.update.enabled": false, "network.captive-portal-service.enabled": false,
          "network.connectivity-service.enabled": false, "browser.safebrowsing.malware.enabled": false,
          "browser.safebrowsing.phishing.enabled": false, "services.settings.server": "http://127.0.0.1:9/",
        },
      },
    } },
  })).sessionId;

  try {
    const id = await wd("POST", `/session/${session}/moz/addon/install`, { path: EXT, temporary: true });
    result.extension_id = String(id).slice(0, 40);
    result.background_observed = Boolean(manifest.background);
  } catch (e) {
    throw new Error(`extension install failed: ${e.message}`);
  }

  const per = Math.max(4000, Math.floor((SECONDS * 1000) / DOMAINS.length));
  for (const host of DOMAINS) {
    await interact(session, host);
    result.pages_visited.push(host);
    await new Promise((r) => setTimeout(r, per));
    if (Date.now() - started > SECONDS * 1000) break;
  }
  await wd("DELETE", `/session/${session}`).catch(() => {});
  clearTimeout(deadline);
  done();
  process.exit(0);
}

main().catch(fail);

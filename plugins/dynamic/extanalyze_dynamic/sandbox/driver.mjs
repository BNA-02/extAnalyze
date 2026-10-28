// In-container observation driver: loads the extension into headless Chromium, browses a set of
// local canary pages that impersonate popular sites, and prints ONE JSON document on stdout.
// Everything is attributed to the extension because the test pages make no external requests.
import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { chromium } from "playwright-core";
import { findHits, newCanaries } from "./canary.mjs";

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => a.replace(/^--/, "").split("=", 2)).map(([k, v]) => [k, v ?? "1"]),
);
const EXT = args.ext || "/ext";
const SECONDS = Math.max(10, Math.min(Number(args.seconds || 45), 300));
const ALLOW_NETWORK = args["allow-network"] === "1";
const BROWSER_PATH = process.env.BROWSER_PATH;
const HTTPS_PORT = 8443;
const HTTP_PORT = 8080;
const MAX_REQUESTS = 500;
const DEBUG_PORT = 9223; // loopback inside the container only
const MAX_NOTES = 50;

// Sites whose content-script match patterns we want to trigger; all resolve to the local server.
const DOMAINS = [
  "www.google.com", "accounts.google.com", "mail.google.com", "www.youtube.com", "www.facebook.com",
  "www.amazon.com", "www.paypal.com", "github.com", "twitter.com", "www.linkedin.com",
  "login.microsoftonline.com", "www.reddit.com", "www.ebay.com", "www.coinbase.com", "www.bankofamerica.com",
];
const LOCAL_HOSTS = new Set([...DOMAINS, "127.0.0.1", "localhost"]);

const canaries = newCanaries();
const notes = [];
const note = (m) => notes.length < MAX_NOTES && notes.push(String(m).slice(0, 300));
const log = (...a) => console.error("[driver]", ...a);

function page(host) {
  return `<!doctype html><html><head><title>${host}</title></head><body>
<h1>${host}</h1>
<form id="login" action="/submit" method="post" onsubmit="return false">
  <input id="email" name="email" type="email" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  <input id="cc" name="cc" autocomplete="cc-number">
  <input id="q" name="q" type="search">
  <button id="submit" type="submit">Sign in</button>
</form>
<script>localStorage.setItem("auth_token", ${JSON.stringify(canaries.storage)});</script>
</body></html>`;
}

function startServers() {
  const handler = (req, res) => {
    const host = (req.headers.host || "localhost").split(":")[0];
    if (req.method === "POST") {
      req.resume();
      res.writeHead(204).end();
      return;
    }
    res.writeHead(200, {
      "content-type": "text/html",
      "set-cookie": [`session=${canaries.cookie}; Path=/`],
    });
    res.end(page(host));
  };
  const tls = { key: fs.readFileSync("/opt/sandbox/key.pem"), cert: fs.readFileSync("/opt/sandbox/cert.pem") };
  https.createServer(tls, handler).listen(HTTPS_PORT, "127.0.0.1");
  http.createServer(handler).listen(HTTP_PORT, "127.0.0.1");
}

const requests = [];
const hits = [];
const externalHosts = new Set();
let bgTargets = 0;

function record(req) {
  recordRaw({
    url: req.url(), method: req.method(), postData: req.postData() ?? "", headers: req.headers(),
    resourceType: req.resourceType(), source: req.serviceWorker() ? "service_worker" : "page",
  });
}

function recordRaw(r) {
  const req = {
    url: () => r.url, method: () => r.method, postData: () => r.postData, headers: () => r.headers,
    resourceType: () => r.resourceType, source: r.source,
  };
  let url;
  try { url = new URL(req.url()); } catch { return; }
  if (!["http:", "https:", "ws:", "wss:"].includes(url.protocol)) return;
  const external = !LOCAL_HOSTS.has(url.hostname);
  if (!external) return;
  externalHosts.add(url.hostname);
  const body = req.postData() ?? "";
  const headers = JSON.stringify(req.headers());
  const found = findHits(`${req.url()}\n${headers}\n${body}`, canaries);
  for (const h of found) {
    hits.push({ canary: h.canary, encoding: h.encoding, url: req.url().slice(0, 300), method: req.method() });
  }
  if (requests.length < MAX_REQUESTS) {
    requests.push({
      url: req.url().slice(0, 300),
      method: req.method(),
      resource_type: req.resourceType(),
      source: req.source,
      body_bytes: Buffer.byteLength(body),
      canaries: found.map((h) => h.canary),
    });
  }
}

// Network events from MV2 background pages, via the browser-level DevTools websocket.
// The background page starts before we can attach, so: attach, enable Network, then reload the
// extension; new background pages are auto-attached paused (waitForDebuggerOnStart) so their very
// first requests are captured.
async function watchBackgroundPages(port) {
  let wsUrl;
  for (let i = 0; i < 20 && !wsUrl; i++) {
    try { wsUrl = (await (await fetch(`http://127.0.0.1:${port}/json/version`)).json()).webSocketDebuggerUrl; }
    catch { await new Promise((r) => setTimeout(r, 250)); }
  }
  if (!wsUrl) return note("devtools endpoint unavailable; background pages not observed");
  const ws = new WebSocket(wsUrl);
  let seq = 0;
  const send = (method, params = {}, sessionId) => ws.send(JSON.stringify({ id: ++seq, method, params, sessionId }));
  let reloaded = false;
  ws.onopen = () => {
    send("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
    send("Target.getTargets");
  };
  ws.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.method === "Target.attachedToTarget") {
      const { sessionId, targetInfo } = m.params;
      if (targetInfo.type === "background_page") {
        bgTargets++;
        send("Network.enable", {}, sessionId);
        if (!reloaded) {
          reloaded = true;
          send("Runtime.evaluate", { expression: "chrome.runtime.reload()" }, sessionId);
        }
      }
      send("Runtime.runIfWaitingForDebugger", {}, sessionId);
    } else if (m.id && m.result?.targetInfos) {
      for (const t of m.result.targetInfos) {
        if (t.type === "background_page") send("Target.attachToTarget", { targetId: t.targetId, flatten: true });
      }
    } else if (m.method === "Network.requestWillBeSent") {
      const r = m.params.request;
      recordRaw({ url: r.url, method: r.method, postData: r.postData ?? "", headers: r.headers ?? {},
                  resourceType: (m.params.type || "other").toLowerCase(), source: "background_page" });
    }
  };
}

async function bgSeen() {
  await new Promise((r) => setTimeout(r, 2000));
  return externalHosts.size > 0 || bgTargets > 0;
}

async function interact(p, host) {
  try {
    await p.goto(`https://${host}:${HTTPS_PORT}/`, { waitUntil: "load", timeout: 15000 });
    await p.type("#email", canaries.email, { delay: 15 });
    await p.type("#password", canaries.password, { delay: 15 });
    await p.type("#cc", canaries.card, { delay: 15 });
    await p.type("#q", canaries.search, { delay: 15 });
    await p.click("#submit");
    await p.mouse.wheel(0, 600);
  } catch (e) {
    note(`interaction failed on ${host}: ${e.message}`);
  }
}

async function main() {
  const started = Date.now();
  startServers();
  const result = {
    schema: 1, background_observed: false, browser: BROWSER_PATH ? path.basename(path.dirname(BROWSER_PATH)) : null,
    extension_id: null, pages_visited: [], requests, external_hosts: [], canary_hits: hits,
    console_errors: [], notes, duration_s: 0,
  };
  const emit = () => {
    result.external_hosts = [...externalHosts].sort();
    result.duration_s = Math.round((Date.now() - started) / 100) / 10;
    process.stdout.write(JSON.stringify(result) + "\n");
  };
  const deadline = setTimeout(() => { note("overall deadline reached"); emit(); process.exit(0); }, SECONDS * 1000 + 15000);

  const userData = fs.mkdtempSync(path.join(os.tmpdir(), "profile-"));
  const rules = DOMAINS.map((d) => `MAP ${d} 127.0.0.1`).join(", ");
  const launchArgs = [
    `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
    `--host-resolver-rules=${rules}`, "--ignore-certificate-errors",
    "--no-first-run", "--disable-gpu", "--disable-dev-shm-usage",
  ];
  if (process.env.MV2) launchArgs.push(`--remote-debugging-port=${DEBUG_PORT}`);
  // Chrome < 132 treats plain --headless as the old headless mode, which cannot load extensions
  if (process.env.MV2) launchArgs.push("--headless=new");
  // Without --allow-network the container itself has no network (docker --network none): external
  // requests fail at DNS but are still observed here.
  const context = await chromium.launchPersistentContext(userData, {
    executablePath: BROWSER_PATH, headless: true, channel: "chromium", args: launchArgs,
    ignoreHTTPSErrors: true, chromiumSandbox: false,
    // Bundled libs apply to the browser only: they must not shadow the hardened base's own libs for node
    env: { ...process.env, LD_LIBRARY_PATH: process.env.BROWSER_LIBS || "" },
  });
  context.on("request", record);
  if (process.env.MV2) watchBackgroundPages(DEBUG_PORT);
  context.on("console", (m) => {
    if (m.type() === "error" && result.console_errors.length < 20) result.console_errors.push(m.text().slice(0, 200));
  });

  let sw = context.serviceWorkers()[0];
  if (!sw) sw = await context.waitForEvent("serviceworker", { timeout: 8000 }).catch(() => null);
  if (sw) {
    result.background_observed = true;
    result.extension_id = (sw.url().match(/chrome-extension:\/\/([a-p]{32})/) || [])[1] ?? null;
  } else if (context.backgroundPages().length || (process.env.MV2 && (await bgSeen()))) {
    result.background_observed = true;
  } else {
    note("no service worker or background page observed (content-script-only extension, or it failed to load)");
  }

  const per = Math.max(4000, Math.floor((SECONDS * 1000) / DOMAINS.length));
  const p = await context.newPage();
  for (const host of DOMAINS) {
    await interact(p, host);
    result.pages_visited.push(host);
    await p.waitForTimeout(per);
    if (Date.now() - started > SECONDS * 1000) break;
  }
  await context.close().catch(() => {});
  clearTimeout(deadline);
  emit();
  process.exit(0);
}

main().catch((e) => {
  process.stdout.write(JSON.stringify({ schema: 1, error: String(e.message || e).slice(0, 500) }) + "\n");
  process.exit(0);
});

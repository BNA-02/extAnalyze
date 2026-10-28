// Code shared by the per-browser drivers: argument parsing, the canary test pages, request
// recording with canary detection, and the result document.
import { findHits, newCanaries } from "./canary.mjs";

export const args = Object.fromEntries(
  process.argv.slice(2).map((a) => a.replace(/^--/, "").split("=", 2)).map(([k, v]) => [k, v ?? "1"]),
);
export const EXT = args.ext || "/ext";
export const SECONDS = Math.max(10, Math.min(Number(args.seconds || 45), 300));
export const ALLOW_NETWORK = args["allow-network"] === "1";
export const HTTPS_PORT = 8443;
export const HTTP_PORT = 8080;

const MAX_REQUESTS = 500;
const MAX_NOTES = 50;

// Sites whose content-script match patterns we want to trigger; all are served locally.
export const DOMAINS = [
  "www.google.com", "accounts.google.com", "mail.google.com", "www.youtube.com", "www.facebook.com",
  "www.amazon.com", "www.paypal.com", "github.com", "twitter.com", "www.linkedin.com",
  "login.microsoftonline.com", "www.reddit.com", "www.ebay.com", "www.coinbase.com", "www.bankofamerica.com",
];
export const LOCAL_HOSTS = new Set([...DOMAINS, "127.0.0.1", "localhost"]);

export const canaries = newCanaries();
export const notes = [];
export const note = (m) => notes.length < MAX_NOTES && notes.push(String(m).slice(0, 300));

export function page(host) {
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

export const cookieHeader = () => `session=${canaries.cookie}; Path=/`;

export const requests = [];
export const hits = [];
export const externalHosts = new Set();

// r: { url, method, postData, headers, resourceType, source }
export function recordRaw(r) {
  let url;
  try { url = new URL(r.url); } catch { return; }
  if (!["http:", "https:", "ws:", "wss:"].includes(url.protocol)) return;
  if (LOCAL_HOSTS.has(url.hostname)) return;
  externalHosts.add(url.hostname);
  const body = r.postData ?? "";
  const found = findHits(`${r.url}\n${JSON.stringify(r.headers ?? {})}\n${body}`, canaries);
  for (const h of found) {
    hits.push({ canary: h.canary, encoding: h.encoding, url: r.url.slice(0, 300), method: r.method });
  }
  if (requests.length < MAX_REQUESTS) {
    requests.push({
      url: r.url.slice(0, 300), method: r.method, resource_type: r.resourceType,
      source: r.source, body_bytes: Buffer.byteLength(body), canaries: found.map((h) => h.canary),
    });
  }
}

export function newResult(browser) {
  return {
    schema: 1, background_observed: false, browser, extension_id: null, pages_visited: [], requests,
    external_hosts: [], canary_hits: hits, console_errors: [], notes, duration_s: 0,
  };
}

export function emit(result, started) {
  result.external_hosts = [...externalHosts].sort();
  result.duration_s = Math.round((Date.now() - started) / 100) / 10;
  process.stdout.write(JSON.stringify(result) + "\n");
}

export function fail(e) {
  process.stdout.write(JSON.stringify({ schema: 1, error: String(e?.message || e).slice(0, 500) }) + "\n");
  process.exit(0);
}

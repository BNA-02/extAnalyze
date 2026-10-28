// Canary tokens and detection of their (possibly encoded) appearance in outbound traffic.
import { randomBytes } from "node:crypto";

export const CANARY_NAMES = ["email", "password", "card", "cookie", "storage", "search"];

export function newCanaries() {
  const out = {};
  for (const name of CANARY_NAMES) out[name] = `xcnry${name.slice(0, 3)}${randomBytes(6).toString("hex")}`;
  return out;
}

// Base64 substrings of `data` that survive being embedded at any byte offset.
function b64Needles(data) {
  const needles = {};
  for (let pad = 0; pad < 3; pad++) {
    const enc = Buffer.concat([Buffer.alloc(pad, 0x41), data]).toString("base64");
    const start = [0, 2, 3][pad]; // leading chars influenced by the padding bytes
    const rem = (pad + data.length) % 3;
    const stripped = enc.replace(/=+$/, "");
    const end = stripped.length - [0, 1, 1][rem]; // last char depends on following bytes
    const needle = stripped.slice(start, end);
    if (needle.length >= 8) {
      needles[`base64@${pad}`] = needle;
      needles[`base64url@${pad}`] = needle.replaceAll("+", "-").replaceAll("/", "_");
    }
  }
  return needles;
}

export function variants(token) {
  const data = Buffer.from(token);
  return {
    raw: token,
    urlencoded: encodeURIComponent(token),
    hex: data.toString("hex"),
    reversed: [...token].reverse().join(""),
    ...b64Needles(data),
  };
}

// Returns [{canary, encoding}] for every canary found in `blob`.
export function findHits(blob, canaries) {
  const hits = [];
  for (const [name, token] of Object.entries(canaries)) {
    for (const [encoding, needle] of Object.entries(variants(token))) {
      if (needle && blob.includes(needle)) {
        hits.push({ canary: name, encoding });
        break;
      }
    }
  }
  return hits;
}

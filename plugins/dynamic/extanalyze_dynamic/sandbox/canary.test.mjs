import test from "node:test";
import assert from "node:assert/strict";
import { findHits, newCanaries } from "./canary.mjs";

const c = { password: "xcnrypas1a2b3c4d5e6f", email: "xcnryema0f1e2d3c4b5a" };
const b64 = (s) => Buffer.from(s).toString("base64");

test("raw, url-encoded and hex", () => {
  assert.equal(findHits(`a=${c.password}`, c)[0].canary, "password");
  assert.equal(findHits(encodeURIComponent(`x ${c.email}`), c)[0].canary, "email");
  assert.equal(findHits(Buffer.from(c.password).toString("hex"), c)[0].encoding, "hex");
});

test("base64 at every alignment, standard and url-safe", () => {
  for (const prefix of ["", "a", "ab", "abc", "{\"k\":\""]) {
    const blob = b64(`${prefix}${c.password}tail`);
    assert.equal(findHits(blob, c)[0]?.canary, "password", `prefix=${JSON.stringify(prefix)}`);
    const urlSafe = blob.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
    assert.equal(findHits(urlSafe, c)[0]?.canary, "password");
  }
});

test("no false positives on unrelated data", () => {
  assert.deepEqual(findHits("hello world " + b64("nothing to see here at all"), c), []);
});

test("canaries are unique per run and per kind", () => {
  const a = newCanaries(), b = newCanaries();
  assert.notEqual(a.password, b.password);
  assert.equal(new Set(Object.values(a)).size, Object.keys(a).length);
});

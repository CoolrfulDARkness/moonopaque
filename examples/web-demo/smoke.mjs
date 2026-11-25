import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..", "..");

function resolveBundlePath() {
  if (process.env.MOONOPAQUE_JS) {
    const p = path.resolve(process.cwd(), process.env.MOONOPAQUE_JS);
    if (!existsSync(p)) {
      throw new Error(`MOONOPAQUE_JS points to a missing file: ${p}`);
    }
    return p;
  }

  const candidates = [
    path.join(repoRoot, "_build", "js", "release", "build", "js_api", "js_api.js"),
    path.join(repoRoot, "_build", "js", "debug", "build", "js_api", "js_api.js"),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error(
    [
      "Could not locate compiled MoonBit JS ESM bundle.",
      "Checked:",
      ...candidates.map((c) => `  - ${c}`),
      "Build it first with:",
      "  moon build js_api --target js --release",
      "Or set MOONOPAQUE_JS=/path/to/js_api.js",
    ].join("\n"),
  );
}

function randHex(bytes = 32) {
  return randomBytes(bytes).toString("hex");
}

function parseOk(res, expectedFields, step) {
  assert.equal(typeof res, "string", `${step}: expected string result`);
  assert.ok(res.startsWith("OK:"), `${step}: expected OK:, got ${res}`);
  const parts = res.slice(3).split("|");
  assert.equal(
    parts.length,
    expectedFields,
    `${step}: expected ${expectedFields} fields, got ${parts.length}`,
  );
  return parts;
}

function flipLastBitHex(hex) {
  const buf = Buffer.from(hex, "hex");
  assert.ok(buf.length > 0, "cannot flip bit on empty hex");
  buf[buf.length - 1] ^= 0x01;
  return buf.toString("hex");
}

function hexBytes(hex) {
  return hex.length / 2;
}

function previewHex(hex) {
  const bytes = hexBytes(hex);
  if (hex.length <= 24) {
    return `${hex} (${bytes} B)`;
  }
  return `${hex.slice(0, 12)}...${hex.slice(-8)} (${bytes} B)`;
}

const SUITES = [
  {
    id: "ristretto255",
    label: "OPAQUE-Ristretto255-SHA512",
    sizes: {
      oprfSeed: 64,
      sk: 32,
      pk: 32,
      regReq: 32,
      regResp: 64,
      record: 192,
      exportKey: 64,
      sessionKey: 64,
      ke1: 96,
      ke2: 320,
      ke3: 64,
    },
  },
  {
    id: "curve25519",
    label: "OPAQUE-Ristretto255-Curve25519-SHA512",
    sizes: {
      oprfSeed: 64,
      sk: 32,
      pk: 32,
      regReq: 32,
      regResp: 64,
      record: 192,
      exportKey: 64,
      sessionKey: 64,
      ke1: 96,
      ke2: 320,
      ke3: 64,
    },
  },
  {
    id: "p256",
    label: "OPAQUE-P256-SHA256",
    sizes: {
      oprfSeed: 32,
      sk: 32,
      pk: 33,
      regReq: 33,
      regResp: 66,
      record: 129,
      exportKey: 32,
      sessionKey: 32,
      ke1: 98,
      ke2: 259,
      ke3: 32,
    },
  },
];

async function main() {
  const bundlePath = resolveBundlePath();
  const opaque = await import(pathToFileURL(bundlePath).href);

  const requiredExports = [
    "server_setup_from_seed",
    "client_register_start",
    "server_register_response",
    "client_register_finish",
    "client_login_start",
    "server_login_start",
    "server_login_fake",
    "client_login_finish",
    "server_login_finish",
  ];
  for (const name of requiredExports) {
    assert.equal(
      typeof opaque[name],
      "function",
      `Missing ESM export: ${name}`,
    );
  }

  console.log("====================================================================");
  console.log("  moonopaque JS ESM End-to-End Smoke Test (Node.js " + process.version + ")");
  console.log("  Bundle: " + bundlePath);
  console.log("====================================================================");

  const totalStart = performance.now();

  for (const suite of SUITES) {
    const t0 = performance.now();
    const context = "moonopaque-js-smoke-v1";
    const credId = "alice@example.com";
    const clientId = "alice@example.com";
    const serverId = "auth.moonopaque.dev";
    const password = "correct-horse-battery-staple";
    const wrongPassword = "wrong-password-12345";

    console.log(`\n[${suite.label}] (${suite.id})`);

    // 1. Server setup
    const [oprfSeed, serverSk, serverPk] = parseOk(
      opaque.server_setup_from_seed(suite.id, randHex(32)),
      3,
      "server_setup_from_seed",
    );
    assert.equal(hexBytes(oprfSeed), suite.sizes.oprfSeed);
    assert.equal(hexBytes(serverSk), suite.sizes.sk);
    assert.equal(hexBytes(serverPk), suite.sizes.pk);

    // 2. Zero-Knowledge Registration
    const [regHandle, regReqHex] = parseOk(
      opaque.client_register_start(suite.id, password, randHex(32)),
      2,
      "client_register_start",
    );
    assert.equal(hexBytes(regReqHex), suite.sizes.regReq);

    const [regRespHex] = parseOk(
      opaque.server_register_response(
        suite.id,
        oprfSeed,
        serverSk,
        serverPk,
        regReqHex,
        credId,
      ),
      1,
      "server_register_response",
    );
    assert.equal(hexBytes(regRespHex), suite.sizes.regResp);

    const [recordHex, regExportKey] = parseOk(
      opaque.client_register_finish(
        suite.id,
        regHandle,
        regRespHex,
        clientId,
        serverId,
        randHex(32),
      ),
      2,
      "client_register_finish",
    );
    assert.equal(hexBytes(recordHex), suite.sizes.record);
    assert.equal(hexBytes(regExportKey), suite.sizes.exportKey);

    // Single-use handle protection
    assert.equal(
      opaque.client_register_finish(
        suite.id,
        regHandle,
        regRespHex,
        clientId,
        serverId,
        randHex(32),
      ),
      "ERR:InvalidHandle",
    );
    console.log(
      `  1. Registration    PASS | Req ${previewHex(regReqHex)} -> Resp ${hexBytes(regRespHex)} B -> Record ${hexBytes(recordHex)} B`,
    );

    // 3. Honest 3DH Login
    const [cHandle, ke1Hex] = parseOk(
      opaque.client_login_start(suite.id, context, password, randHex(32)),
      2,
      "client_login_start",
    );
    assert.equal(hexBytes(ke1Hex), suite.sizes.ke1);

    const [sHandle, ke2Hex] = parseOk(
      opaque.server_login_start(
        suite.id,
        context,
        oprfSeed,
        serverSk,
        serverPk,
        recordHex,
        credId,
        clientId,
        serverId,
        ke1Hex,
        randHex(32),
        randHex(32),
        randHex(32),
      ),
      2,
      "server_login_start",
    );
    assert.equal(hexBytes(ke2Hex), suite.sizes.ke2);

    const [ke3Hex, clientSessionKey, loginExportKey] = parseOk(
      opaque.client_login_finish(
        suite.id,
        context,
        cHandle,
        clientId,
        serverId,
        ke2Hex,
      ),
      3,
      "client_login_finish",
    );
    assert.equal(hexBytes(ke3Hex), suite.sizes.ke3);
    assert.equal(hexBytes(clientSessionKey), suite.sizes.sessionKey);
    assert.equal(hexBytes(loginExportKey), suite.sizes.exportKey);

    const [serverSessionKey] = parseOk(
      opaque.server_login_finish(sHandle, ke3Hex),
      1,
      "server_login_finish",
    );
    assert.equal(clientSessionKey, serverSessionKey, "session_key mismatch");
    assert.equal(loginExportKey, regExportKey, "export_key mismatch");

    // Consumed handles cannot be replayed
    assert.equal(
      opaque.client_login_finish(suite.id, context, cHandle, clientId, serverId, ke2Hex),
      "ERR:InvalidHandle",
    );
    assert.equal(opaque.server_login_finish(sHandle, ke3Hex), "ERR:InvalidHandle");
    console.log(
      `  2. 3DH Login       PASS | KE1 ${hexBytes(ke1Hex)} B -> KE2 ${hexBytes(ke2Hex)} B -> KE3 ${hexBytes(ke3Hex)} B | session_key=${previewHex(clientSessionKey)}`,
    );

    // 4. Unknown User Anti-Enumeration Fake KE2
    const [ghostCHandle, ghostKe1Hex] = parseOk(
      opaque.client_login_start(suite.id, context, "guess-password", randHex(32)),
      2,
      "client_login_start(unknown)",
    );
    const [ghostSHandle, fakeKe2Hex] = parseOk(
      opaque.server_login_fake(
        suite.id,
        context,
        oprfSeed,
        serverSk,
        serverPk,
        "ghost@example.com",
        "ghost@example.com",
        serverId,
        ghostKe1Hex,
        randHex(32),
      ),
      2,
      "server_login_fake",
    );
    assert.equal(
      hexBytes(fakeKe2Hex),
      hexBytes(ke2Hex),
      "Fake KE2 byte length must match real KE2",
    );
    assert.equal(
      opaque.client_login_finish(
        suite.id,
        context,
        ghostCHandle,
        "ghost@example.com",
        serverId,
        fakeKe2Hex,
      ),
      "ERR:InvalidEnvelopeTag",
    );
    assert.equal(
      opaque.server_login_finish(ghostSHandle, ke3Hex),
      "ERR:InvalidClientMac",
    );
    console.log(
      `  3. Anti-Enum Fake  PASS | Fake KE2 ${hexBytes(fakeKe2Hex)} B === Real KE2 ${hexBytes(ke2Hex)} B -> ERR:InvalidEnvelopeTag`,
    );

    // 5. Wrong Password Rejection
    const [badCHandle, badKe1Hex] = parseOk(
      opaque.client_login_start(suite.id, context, wrongPassword, randHex(32)),
      2,
      "client_login_start(wrong pw)",
    );
    const [badSHandle, badKe2Hex] = parseOk(
      opaque.server_login_start(
        suite.id,
        context,
        oprfSeed,
        serverSk,
        serverPk,
        recordHex,
        credId,
        clientId,
        serverId,
        badKe1Hex,
        randHex(32),
        randHex(32),
        randHex(32),
      ),
      2,
      "server_login_start(wrong pw)",
    );
    assert.equal(
      opaque.client_login_finish(
        suite.id,
        context,
        badCHandle,
        clientId,
        serverId,
        badKe2Hex,
      ),
      "ERR:InvalidEnvelopeTag",
    );
    assert.equal(
      opaque.server_login_finish(badSHandle, ke3Hex),
      "ERR:InvalidClientMac",
    );
    console.log(
      "  4. Wrong Password  PASS | Constant-time envelope auth_tag -> ERR:InvalidEnvelopeTag",
    );

    // 6. Active MITM Tampered MAC Rejection (KE2 server_mac & KE3 client_mac)
    const [mitm2CHandle, mitm2Ke1Hex] = parseOk(
      opaque.client_login_start(suite.id, context, password, randHex(32)),
      2,
      "client_login_start(mitm ke2)",
    );
    const [mitm2SHandle, mitm2Ke2Hex] = parseOk(
      opaque.server_login_start(
        suite.id,
        context,
        oprfSeed,
        serverSk,
        serverPk,
        recordHex,
        credId,
        clientId,
        serverId,
        mitm2Ke1Hex,
        randHex(32),
        randHex(32),
        randHex(32),
      ),
      2,
      "server_login_start(mitm ke2)",
    );
    assert.equal(
      opaque.client_login_finish(
        suite.id,
        context,
        mitm2CHandle,
        clientId,
        serverId,
        flipLastBitHex(mitm2Ke2Hex),
      ),
      "ERR:InvalidServerMac",
    );
    assert.equal(
      opaque.server_login_finish(mitm2SHandle, ke3Hex),
      "ERR:InvalidClientMac",
    );

    const [mitm3CHandle, mitm3Ke1Hex] = parseOk(
      opaque.client_login_start(suite.id, context, password, randHex(32)),
      2,
      "client_login_start(mitm ke3)",
    );
    const [mitm3SHandle, mitm3Ke2Hex] = parseOk(
      opaque.server_login_start(
        suite.id,
        context,
        oprfSeed,
        serverSk,
        serverPk,
        recordHex,
        credId,
        clientId,
        serverId,
        mitm3Ke1Hex,
        randHex(32),
        randHex(32),
        randHex(32),
      ),
      2,
      "server_login_start(mitm ke3)",
    );
    const [mitm3Ke3Hex] = parseOk(
      opaque.client_login_finish(
        suite.id,
        context,
        mitm3CHandle,
        clientId,
        serverId,
        mitm3Ke2Hex,
      ),
      3,
      "client_login_finish(mitm ke3)",
    );
    assert.equal(
      opaque.server_login_finish(mitm3SHandle, flipLastBitHex(mitm3Ke3Hex)),
      "ERR:InvalidClientMac",
    );
    console.log(
      "  5. MITM Tamper     PASS | KE2 1-bit -> ERR:InvalidServerMac | KE3 1-bit -> ERR:InvalidClientMac",
    );

    const elapsed = (performance.now() - t0).toFixed(1);
    console.log(`  Suite elapsed: ${elapsed} ms`);
  }

  // 7. UTF-8 Unicode Password & Identity Roundtrip Check
  {
    const suiteId = "ristretto255";
    const utf8Context = "上下文-OPAQUE-🔐";
    const utf8User = "用户@example.com";
    const utf8Server = "服务器.moonopaque.dev";
    const utf8Password = "密码🔑-OPAQUE-日本語";
    const [oprfSeed, serverSk, serverPk] = parseOk(
      opaque.server_setup_from_seed(suiteId, randHex(32)),
      3,
      "utf8 server_setup",
    );
    const [regH, regReq] = parseOk(
      opaque.client_register_start(suiteId, utf8Password, randHex(32)),
      2,
      "utf8 reg_start",
    );
    const [regResp] = parseOk(
      opaque.server_register_response(suiteId, oprfSeed, serverSk, serverPk, regReq, utf8User),
      1,
      "utf8 reg_resp",
    );
    const [recHex, regExp] = parseOk(
      opaque.client_register_finish(suiteId, regH, regResp, utf8User, utf8Server, randHex(32)),
      2,
      "utf8 reg_finish",
    );
    const [cH, ke1] = parseOk(
      opaque.client_login_start(suiteId, utf8Context, utf8Password, randHex(32)),
      2,
      "utf8 login_start",
    );
    const [sH, ke2] = parseOk(
      opaque.server_login_start(
        suiteId,
        utf8Context,
        oprfSeed,
        serverSk,
        serverPk,
        recHex,
        utf8User,
        utf8User,
        utf8Server,
        ke1,
        randHex(32),
        randHex(32),
        randHex(32),
      ),
      2,
      "utf8 server_login_start",
    );
    const [ke3, cSk, lExp] = parseOk(
      opaque.client_login_finish(suiteId, utf8Context, cH, utf8User, utf8Server, ke2),
      3,
      "utf8 client_login_finish",
    );
    const [sSk] = parseOk(opaque.server_login_finish(sH, ke3), 1, "utf8 server_login_finish");
    assert.equal(cSk, sSk, "utf8 session_key mismatch");
    assert.equal(lExp, regExp, "utf8 export_key mismatch");
    console.log("\n[UTF-8 Unicode Roundtrip] PASS | Chinese + Japanese + Emoji password & identities");
  }

  const totalElapsed = (performance.now() - totalStart).toFixed(1);
  console.log("\n====================================================================");
  console.log(
    `  ALL 3 RFC 9807 SUITES + UTF-8 PASSED (16/16 checks in ${totalElapsed} ms)`,
  );
  console.log("====================================================================");
}

main().catch((err) => {
  console.error("\n[SMOKE TEST FAILED]");
  console.error(err);
  process.exit(1);
});

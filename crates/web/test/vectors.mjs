// Checks the WebAssembly core embedded in psm.html against the test vectors,
// and that the page's Content-Security-Policy admits its inline code.
//
//   node crates/web/test/vectors.mjs target/web/psm.html spec/vectors-v1.json

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const [htmlPath, vectorsPath] = process.argv.slice(2);
const html = readFileSync(htmlPath, "ascii");
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));

let failures = 0;
function check(label, actual, expected) {
  if (actual !== expected) {
    failures += 1;
    console.log(`FAIL ${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

// A browser refuses to run inline code whose hash the policy does not list.
const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]*)"/)[1];
let inline = 0;
for (const [, tag, body] of html.matchAll(/<(script|style)\b[^>]*>([\s\S]*?)<\/\1>/g)) {
  const hash = `'sha256-${createHash("sha256").update(body).digest("base64")}'`;
  check(`policy lists inline ${tag} #${inline}`, csp.includes(hash), true);
  inline += 1;
}
check("policy blocks the network", csp.startsWith("default-src 'none';"), true);

// Load the core exactly as the page does.
vm.runInThisContext(html.match(/<script id="psm-core">([\s\S]*?)<\/script>/)[1]);
const psm = vm.runInThisContext("wasm_bindgen");
await psm({ module_or_path: Buffer.from(vm.runInThisContext("PSM_WASM"), "base64") });

check("algorithm", psm.algorithm(), vectors.algorithm);
const normalize = { text: psm.normalizeText, site: psm.normalizeSite };
let normalized = 0;
for (const c of vectors.normalization) {
  // Secret normalization happens inside Session and is not exported.
  if (c.function in normalize) {
    check(`${c.function}(${JSON.stringify(c.input)})`, normalize[c.function](c.input), c.output);
    normalized += 1;
  }
}

let passwords = 0;
for (const root of vectors.roots) {
  const session = new psm.Session(root.identity, root.secret);
  check(`fingerprint for ${JSON.stringify(root.identity)}`, session.fingerprint, root.fingerprint);
  for (const c of root.passwords) {
    const actual = session.password(c.site, c.account, c.generation, c.profile, c.length);
    check(`password ${JSON.stringify([c.site, c.account, c.generation, c.profile, c.length])}`, actual, c.password);
    passwords += 1;
  }
  session.free();
}

function error(f) {
  try {
    f();
    return "no error";
  } catch (e) {
    return e.message;
  }
}
check("empty identity", error(() => new psm.Session(" ", "x")), "identity is empty");
const session = new psm.Session("Test User", "correct horse battery staple");
check("default length", session.password("github.com", "", 1, "standard", 0), vectors.roots[0].passwords[0].password);
check("bad profile", error(() => session.password("a.com", "", 1, "strong", 0)).startsWith("unknown profile"), true);
check("bad length", error(() => session.password("a.com", "", 1, "standard", 7)), "length 7 is outside 8..64 for profile standard");
session.free();
check("selftest", psm.selftest() > 0, true);

console.log(`${inline} inline blocks, ${normalized} normalization cases, ${vectors.roots.length} root keys, ${passwords} passwords`);
if (failures > 0) {
  console.log(`${failures} FAILURES`);
  process.exit(1);
}
console.log("psm.html: all checks passed");

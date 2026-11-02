// Drives psm.html in headless Firefox over WebDriver BiDi: the real file from
// a file:// URL, with its Content-Security-Policy in force. Unlocks with two
// test-vector identities, generates passwords, runs the self-test and locks.
//
//   node crates/web/test/browser.mjs target/web/psm.html spec/vectors-v1.json
//
// Set FIREFOX to use a Firefox other than the one on PATH.

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const [htmlPath, vectorsPath] = process.argv.slice(2);
const page = path.resolve(htmlPath);
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));

let failures = 0;
function check(label, actual, expected) {
  if (actual !== expected) {
    failures += 1;
    console.log(`FAIL ${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

// Snap-packaged Firefox can only use a profile under the home directory, so
// the throwaway profile lives next to the page.
const profile = mkdtempSync(path.join(path.dirname(page), "firefox-"));
const firefox = spawn(
  process.env.FIREFOX ?? "firefox",
  ["--headless", "--no-remote", "--profile", profile, "--remote-debugging-port", "0"],
  { stdio: ["ignore", "ignore", "pipe"] },
);

let send = null;
try {
  // Firefox announces its endpoint on stderr, except when snap-packaged; it
  // also writes it into the profile.
  const endpoint = await new Promise((found, reject) => {
    let log = "";
    let poll = 0;
    const timeout = setTimeout(() => {
      clearInterval(poll);
      reject(new Error(`firefox did not start WebDriver BiDi: ${log}`));
    }, 60000);
    const resolve = (url) => {
      clearInterval(poll);
      clearTimeout(timeout);
      found(url);
    };
    firefox.stderr.on("data", (chunk) => {
      log += chunk;
      const match = log.match(/WebDriver BiDi listening on (ws:\/\/\S+)/);
      if (match) {
        resolve(match[1]);
      }
    });
    const announced = path.join(profile, "WebDriverBiDiServer.json");
    poll = setInterval(() => {
      if (existsSync(announced)) {
        const { ws_host: host, ws_port: port } = JSON.parse(readFileSync(announced, "utf8"));
        resolve(`ws://${host}:${port}`);
      }
    }, 100);
  });

  const socket = new WebSocket(`${endpoint}/session`);
  await new Promise((resolve, reject) => {
    socket.onopen = resolve;
    socket.onerror = () => reject(new Error(`cannot connect to ${endpoint}`));
  });
  const pending = new Map();
  let lastId = 0;
  socket.onmessage = (event) => {
    const message = JSON.parse(event.data);
    const call = pending.get(message.id);
    if (call !== undefined) {
      pending.delete(message.id);
      if (message.type === "error") {
        call.reject(new Error(`${message.error}: ${message.message}`));
      } else {
        call.resolve(message.result);
      }
    }
  };
  send = (method, params) =>
    new Promise((resolve, reject) => {
      lastId += 1;
      pending.set(lastId, { resolve, reject });
      socket.send(JSON.stringify({ id: lastId, method, params }));
    });

  await send("session.new", { capabilities: {} });
  const { contexts } = await send("browsingContext.getTree", {});
  const context = contexts[0].context;
  await send("browsingContext.navigate", { context, url: pathToFileURL(page).href, wait: "complete" });

  async function evaluate(expression) {
    const result = await send("script.evaluate", { expression, target: { context }, awaitPromise: true });
    if (result.type === "exception") {
      throw new Error(`${expression}: ${result.exceptionDetails.text}`);
    }
    return result.result.value;
  }
  async function waitFor(expression) {
    const deadline = Date.now() + 60000;
    for (;;) {
      const value = await evaluate(expression);
      if (value) {
        return value;
      }
      if (Date.now() > deadline) {
        throw new Error(`timed out waiting for ${expression}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  const text = (id) => evaluate(`document.getElementById(${JSON.stringify(id)}).textContent`);
  const value = (id) => evaluate(`document.getElementById(${JSON.stringify(id)}).value`);
  const set = (id, v) =>
    evaluate(`(() => {
      const e = document.getElementById(${JSON.stringify(id)});
      e.value = ${JSON.stringify(v)};
      e.dispatchEvent(new Event("input", { bubbles: true }));
    })()`);
  const click = (id) => evaluate(`document.getElementById(${JSON.stringify(id)}).click()`);

  // The app has started once it has filled in the profile picker; that needs
  // both inline scripts and the WebAssembly core, so the policy admitted them.
  await waitFor(`document.getElementById("profile").options.length === 4`);

  for (const root of vectors.roots.slice(0, 2)) {
    const c = root.passwords[0];
    await set("identity", root.identity);
    await set("secret", root.secret);
    await click("unlock");
    check(`fingerprint for ${JSON.stringify(root.identity)}`, await waitFor(`document.getElementById("fingerprint").textContent`), root.fingerprint);
    check("secret field cleared", await value("secret"), "");

    await set("site", c.site);
    check("site hint", await text("site-hint"), `Site: ${c.normalized_site}`);
    await set("account", c.account);
    await set("generation", String(c.generation));
    await set("length", String(c.length));
    await evaluate(`(() => {
      const e = document.getElementById("profile");
      e.value = ${JSON.stringify(c.profile)};
      e.dispatchEvent(new Event("change"));
    })()`);
    await click("generate");
    check("password hidden at first", await text("password"), String.fromCharCode(0x2022).repeat(c.password.length));
    await click("show");
    check(`password for ${c.site}`, await text("password"), c.password);

    await click("lock");
    check("locked", await evaluate(`document.getElementById("generate-section").hidden`), true);
    check("fingerprint cleared", await text("fingerprint"), "");
  }

  await click("selftest");
  const selftest = await waitFor(`(() => {
    const s = document.getElementById("selftest-status").textContent;
    return s.startsWith("Passed") || s.startsWith("FAILED") ? s : "";
  })()`);
  check("self-test", selftest.startsWith("Passed"), true);

} finally {
  // Closing over the protocol works even where signals cannot reach a
  // sandboxed Firefox.
  if (send !== null) {
    await Promise.race([send("browser.close", {}), new Promise((resolve) => setTimeout(resolve, 5000))]).catch(() => {});
  }
  try {
    firefox.kill();
  } catch {
    // Already gone, or out of reach of signals.
  }
  // Firefox writes to its profile while shutting down.
  await new Promise((resolve) => {
    if (firefox.exitCode !== null) {
      resolve();
    }
    firefox.once("exit", resolve);
    setTimeout(resolve, 10000).unref();
  });
  rmSync(profile, { recursive: true, force: true });
}

if (failures > 0) {
  console.log(`${failures} FAILURES`);
  process.exit(1);
}
console.log("psm.html in Firefox: all checks passed");

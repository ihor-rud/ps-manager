"use strict";

// The browser app. All password logic lives in the WebAssembly core
// (`wasm_bindgen`, from crates/web); this script only wires up the page.
(async () => {
  const CLEAR_CLIPBOARD_MS = 20 * 1000;
  const HIDE_PASSWORD_MS = 60 * 1000;
  const LOCK_IDLE_MS = 5 * 60 * 1000;
  const MAX_U32 = 4294967295;
  const DOT = String.fromCharCode(0x2022);

  const psm = wasm_bindgen;
  const $ = (id) => document.getElementById(id);
  const ui = {
    unlockSection: $("unlock-section"),
    identity: $("identity"),
    secret: $("secret"),
    unlock: $("unlock"),
    unlockStatus: $("unlock-status"),
    generateSection: $("generate-section"),
    fingerprint: $("fingerprint"),
    site: $("site"),
    siteHint: $("site-hint"),
    account: $("account"),
    generation: $("generation"),
    length: $("length"),
    profile: $("profile"),
    profileHint: $("profile-hint"),
    generate: $("generate"),
    generateStatus: $("generate-status"),
    result: $("result"),
    password: $("password"),
    copy: $("copy"),
    show: $("show"),
    resultStatus: $("result-status"),
    lock: $("lock"),
    algorithm: $("algorithm"),
    selftest: $("selftest"),
    selftestStatus: $("selftest-status"),
  };

  let session = null;
  let password = "";
  let shown = false;
  let lastActivity = Date.now();
  let clipboardDue = 0;
  let idleTimer = 0;
  let hideTimer = 0;
  let clipboardTimer = 0;

  function status(element, message, kind) {
    element.textContent = message;
    element.className = kind ? `status ${kind}` : "status";
  }

  // Lets the browser paint a status message before a long computation.
  function paint() {
    return new Promise((resolve) => requestAnimationFrame(() => setTimeout(resolve, 0)));
  }

  function wholeNumber(input, fallback) {
    const text = input.value.trim();
    if (text === "") {
      return fallback;
    }
    const value = Number(text);
    return Number.isInteger(value) && value >= 0 && value <= MAX_U32 ? value : null;
  }

  // Clipboard

  async function writeClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        // Fall back to the older API below.
      }
    }
    const area = document.createElement("textarea");
    // An empty selection copies nothing, so clearing writes a space instead.
    area.value = text === "" ? " " : text;
    area.readOnly = true;
    area.className = "offscreen";
    document.body.append(area);
    area.select();
    let copied = false;
    try {
      copied = document.execCommand("copy");
    } catch {
      copied = false;
    }
    area.remove();
    return copied;
  }

  // Browsers only allow clipboard writes from a visible page, so a clear that
  // falls due in the background happens when the page is shown again.
  async function clearClipboardIfDue() {
    if (clipboardDue === 0 || Date.now() < clipboardDue || document.hidden) {
      return;
    }
    if (await writeClipboard("")) {
      clipboardDue = 0;
      status(ui.resultStatus, "Clipboard cleared.", "ok");
    }
  }

  async function copy() {
    if (!(await writeClipboard(password))) {
      status(ui.resultStatus, "This browser blocked copying; show the password and copy it by hand.", "error");
      return;
    }
    clipboardDue = Date.now() + CLEAR_CLIPBOARD_MS;
    clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(clearClipboardIfDue, CLEAR_CLIPBOARD_MS);
    status(ui.resultStatus, `Copied. Cleared from the clipboard in ${CLEAR_CLIPBOARD_MS / 1000} s while this page is open.`, "ok");
  }

  // Password display

  function renderPassword() {
    ui.password.textContent = shown ? password : DOT.repeat(password.length);
    ui.show.textContent = shown ? "Hide" : "Show";
  }

  function clearResult() {
    clearTimeout(hideTimer);
    password = "";
    shown = false;
    ui.password.textContent = "";
    ui.result.hidden = true;
    status(ui.resultStatus, "");
  }

  function generate() {
    const generation = wholeNumber(ui.generation, 1);
    const length = wholeNumber(ui.length, 0);
    if (generation === null || generation < 1) {
      status(ui.generateStatus, "Generation must be a whole number of at least 1.", "error");
      return;
    }
    if (length === null) {
      status(ui.generateStatus, "Length must be a whole number.", "error");
      return;
    }
    clearResult();
    try {
      password = session.password(ui.site.value, ui.account.value, generation, ui.profile.value, length);
    } catch (e) {
      status(ui.generateStatus, e.message, "error");
      return;
    }
    status(ui.generateStatus, "");
    renderPassword();
    ui.result.hidden = false;
    hideTimer = setTimeout(clearResult, HIDE_PASSWORD_MS);
  }

  // Unlocking and locking

  async function unlock() {
    ui.unlock.disabled = true;
    status(ui.unlockStatus, "Deriving the key; this takes a few seconds...");
    await paint();
    try {
      session = new psm.Session(ui.identity.value, ui.secret.value);
    } catch (e) {
      status(ui.unlockStatus, e.message, "error");
      return;
    } finally {
      ui.secret.value = "";
      ui.unlock.disabled = false;
    }
    status(ui.unlockStatus, "");
    ui.fingerprint.textContent = session.fingerprint;
    ui.unlockSection.hidden = true;
    ui.generateSection.hidden = false;
    touch();
    ui.site.focus();
  }

  function lock(message) {
    if (session !== null) {
      session.free();
      session = null;
    }
    clearTimeout(idleTimer);
    clearResult();
    for (const input of [ui.site, ui.account, ui.length]) {
      input.value = "";
    }
    ui.generation.value = "1";
    ui.siteHint.textContent = "";
    status(ui.generateStatus, "");
    ui.fingerprint.textContent = "";
    ui.generateSection.hidden = true;
    ui.unlockSection.hidden = false;
    status(ui.unlockStatus, message || "");
  }

  function touch() {
    if (session === null) {
      return;
    }
    lastActivity = Date.now();
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => lock("Locked after 5 minutes without use."), LOCK_IDLE_MS);
  }

  // Inputs

  function showProfile() {
    const option = ui.profile.selectedOptions[0];
    ui.length.placeholder = option.dataset.default;
    ui.length.min = option.dataset.min;
    ui.length.max = option.dataset.max;
    ui.profileHint.textContent = `${option.dataset.description}; ${option.dataset.min} to ${option.dataset.max} characters.`;
  }

  function showSite() {
    if (ui.site.value.trim() === "") {
      ui.siteHint.textContent = "";
      return;
    }
    const site = psm.normalizeSite(ui.site.value);
    ui.siteHint.textContent = site === "" ? "Not a usable site name." : `Site: ${site}`;
  }

  async function selftest() {
    ui.selftest.disabled = true;
    status(ui.selftestStatus, "Running...");
    await paint();
    try {
      status(ui.selftestStatus, `Passed: ${psm.selftest()} passwords match.`, "ok");
    } catch (e) {
      status(ui.selftestStatus, `FAILED: ${e.message}`, "error");
    } finally {
      ui.selftest.disabled = false;
    }
  }

  // Start-up

  try {
    const bytes = Uint8Array.from(atob(PSM_WASM), (c) => c.charCodeAt(0));
    await psm({ module_or_path: bytes });
  } catch (e) {
    status(ui.unlockStatus, `This browser cannot run the password engine: ${e.message}`, "error");
    ui.unlock.disabled = true;
    return;
  }

  ui.algorithm.textContent = psm.algorithm();
  for (const profile of psm.profiles()) {
    const option = new Option(profile.name, profile.name);
    option.dataset.default = String(profile.defaultLength);
    option.dataset.min = String(profile.minLength);
    option.dataset.max = String(profile.maxLength);
    option.dataset.description = profile.description;
    ui.profile.append(option);
    profile.free();
  }
  showProfile();

  const onEnter = (action) => (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      action();
    }
  };
  ui.unlock.addEventListener("click", unlock);
  ui.identity.addEventListener("keydown", onEnter(() => ui.secret.focus()));
  ui.secret.addEventListener("keydown", onEnter(unlock));
  ui.generate.addEventListener("click", generate);
  for (const input of [ui.site, ui.account, ui.generation, ui.length]) {
    input.addEventListener("keydown", onEnter(generate));
  }
  ui.site.addEventListener("input", showSite);
  ui.profile.addEventListener("change", showProfile);
  ui.copy.addEventListener("click", copy);
  ui.show.addEventListener("click", () => {
    shown = !shown;
    renderPassword();
  });
  ui.lock.addEventListener("click", () => lock(""));
  ui.selftest.addEventListener("click", selftest);

  for (const type of ["click", "input", "keydown"]) {
    document.addEventListener(type, touch, true);
  }
  // Timers are paused while the page is in the background, so catch up when
  // it comes back.
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      return;
    }
    if (session !== null && Date.now() - lastActivity >= LOCK_IDLE_MS) {
      lock("Locked after 5 minutes without use.");
    }
    clearClipboardIfDue();
  });
  window.addEventListener("pagehide", () => lock(""));

  if (location.hash === "#selftest") {
    selftest();
  }
})();

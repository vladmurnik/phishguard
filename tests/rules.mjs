// Browser-free tests for the service worker: escalation rules, allowlist,
// badges, tab state. A fake `chrome` API is installed before background.js is
// imported, so the real module code runs unmodified.
//
//   node tests/rules.mjs
//
// Exits non-zero if anything the user would see is wrong.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------- fake chrome
const log = { badges: [], tabsGone: new Set(), tabs: new Map(), store: {} };
const listeners = { updated: [], activated: [], removed: [], message: [] };

const asyncOk = (value) => Promise.resolve(value);

globalThis.chrome = {
  storage: {
    local: {
      get: (key) => asyncOk({ [key]: log.store[key] }),
      set: (obj) => {
        Object.assign(log.store, obj);
        return asyncOk(undefined);
      },
    },
  },
  tabs: {
    onUpdated: { addListener: (f) => listeners.updated.push(f) },
    onActivated: { addListener: (f) => listeners.activated.push(f) },
    onRemoved: { addListener: (f) => listeners.removed.push(f) },
    get: (id) =>
      log.tabs.has(id) && !log.tabsGone.has(id)
        ? asyncOk({ id, url: log.tabs.get(id) })
        : Promise.reject(new Error(`No tab with id: ${id}.`)),
  },
  action: {
    setBadgeText: ({ tabId, text }) => {
      log.badges.push({ tabId, kind: "text", value: text });
      return asyncOk(undefined);
    },
    setBadgeBackgroundColor: ({ tabId, color }) => {
      log.badges.push({ tabId, kind: "color", value: color });
      return asyncOk(undefined);
    },
  },
  runtime: {
    onMessage: { addListener: (f) => listeners.message.push(f) },
  },
};

const { escalate, scan, handleMessage, tabState, BADGE } = await import("../src/background.js");

const send = (msg, sender = {}) =>
  new Promise((resolve) => {
    const keepAlive = listeners.message[0](msg, sender, resolve);
    if (keepAlive !== true) resolve(null);
  });

const tick = () => new Promise((r) => setTimeout(r, 0));
const lastBadge = () => {
  const text = [...log.badges].reverse().find((b) => b.kind === "text");
  const color = [...log.badges].reverse().find((b) => b.kind === "color");
  return [text?.value, color?.value];
};
const reset = () => {
  log.badges.length = 0;
  log.store = {};
  log.tabs.clear();
  log.tabsGone.clear();
  tabState.clear();
};

// ------------------------------------------------------------------ assertions
let failed = 0;
let passed = 0;
function check(name, ok, detail = "") {
  if (ok) {
    passed += 1;
    console.log(`PASS  ${name}`);
  } else {
    failed += 1;
    console.log(`FAIL  ${name}${detail ? `  — ${detail}` : ""}`);
  }
}

const CLEAN = "https://github.com/vladmurnik/kaggle-conveyor";
const PHISH = "https://sberbank-online-verify.ru/login";
const PAGE_CLEAN = { https: true, hasPassword: true, passwordCount: 1, hasCardField: false, brandInTitle: "", brandInDomain: false };

// ------------------------------------------------------------------ escalation
{
  reset();
  const res = escalate(await scan(CLEAN), PAGE_CLEAN);
  check("clean https login page stays safe", res.level === "safe", `got ${res.level} p=${res.p.toFixed(4)}`);
  check("clean page has no notes", res.notes.length === 0, JSON.stringify(res.notes));
}

{
  reset();
  const res = escalate(await scan(CLEAN), { ...PAGE_CLEAN, https: false });
  check("password form without HTTPS -> danger", res.level === "danger", `got ${res.level}`);
  check("...and says why", res.notes.some((n) => /HTTPS/i.test(n)), JSON.stringify(res.notes));
}

{
  reset();
  const res = escalate(await scan(CLEAN), { ...PAGE_CLEAN, brandInTitle: "paypal", brandInDomain: false });
  check("brand in title, not in domain -> warn", res.level === "warn", `got ${res.level}`);
  check("...and names the brand", res.notes.some((n) => n.includes("paypal")), JSON.stringify(res.notes));
}

{
  reset();
  const res = escalate(await scan(CLEAN), { ...PAGE_CLEAN, brandInTitle: "paypal", brandInDomain: true });
  check("brand in title AND in domain does not escalate", res.level === "safe", `got ${res.level}`);
}

{
  reset();
  const res = escalate(await scan(CLEAN), { ...PAGE_CLEAN, hasPassword: true, passwordCount: 1, hasCardField: true });
  check("password + card fields -> danger", res.level === "danger", `got ${res.level}`);
}

{
  reset();
  const res = escalate(await scan(CLEAN), { https: false, hasPassword: false, passwordCount: 0, hasCardField: true, brandInTitle: "", brandInDomain: false });
  check("no password field -> rules stay silent", res.level === "safe" && res.notes.length === 0, JSON.stringify(res));
}

{
  reset();
  const res = escalate(await scan(PHISH), { https: true, hasPassword: true, passwordCount: 1, hasCardField: false, brandInTitle: "", brandInDomain: false });
  check("model alone flags the lookalike domain", res.level === "danger", `got ${res.level} p=${res.p.toFixed(4)}`);
  check("escalation never downgrades a danger", res.level === "danger");
}

{
  reset();
  const res = escalate(await scan(PHISH), { https: true, hasPassword: true, passwordCount: 1, hasCardField: false, brandInTitle: "sberbank", brandInDomain: false });
  check("danger + brand note keeps danger", res.level === "danger" && res.notes.length === 1, `got ${res.level} ${JSON.stringify(res.notes)}`);
}

// ------------------------------------------------------------------ allowlist
{
  reset();
  const first = await send({ type: "allow", domain: "github.com" });
  check("allow stores the domain", first.allow.length === 1 && first.allow[0] === "github.com", JSON.stringify(first));

  const twice = await send({ type: "allow", domain: "github.com" });
  check("allow is idempotent", twice.allow.length === 1, JSON.stringify(twice));

  const res = await send({ type: "credential", url: CLEAN, page: { ...PAGE_CLEAN, https: false } }, { tab: { id: 3 } });
  check("allowlisted domain overrides even the HTTPS rule", res.level === "allowed", `got ${res.level}`);
  check("allowlisted domain has no reasons", res.why.length === 0 && res.notes.length === 0);

  const st = await send({ type: "state", tabId: 3 });
  check("tab state remembers 'allowed'", st?.level === "allowed", JSON.stringify(st));

  const removed = await send({ type: "unallow", domain: "github.com" });
  check("unallow empties the list", removed.allow.length === 0, JSON.stringify(removed));

  const back = await send({ type: "credential", url: CLEAN, page: PAGE_CLEAN }, { tab: { id: 3 } });
  check("after unallow the page is judged again", back.level === "safe", `got ${back.level}`);

  const noop = await send({ type: "allow", domain: "" });
  check("empty domain is ignored", noop.allow.length === 0, JSON.stringify(noop));
}

// ------------------------------------------------------------------ badges
{
  reset();
  await send({ type: "credential", url: CLEAN, page: { ...PAGE_CLEAN, https: false } }, { tab: { id: 7 } });
  await tick();
  const [text, color] = lastBadge();
  check("danger badge is '!!' in red", text === "!!" && color === "#c62828", `${text} / ${color}`);

  reset();
  await send({ type: "credential", url: CLEAN, page: { ...PAGE_CLEAN, brandInTitle: "paypal", brandInDomain: false } }, { tab: { id: 8 } });
  await tick();
  const [wtext, wcolor] = lastBadge();
  check("warn badge is '!' in amber", wtext === "!" && wcolor === "#f9a825", `${wtext} / ${wcolor}`);

  reset();
  await send({ type: "credential", url: CLEAN, page: PAGE_CLEAN }, { tab: { id: 9 } });
  await tick();
  const [stext, scolor] = lastBadge();
  check("safe badge is empty text in green", stext === "" && scolor === "#2e7d32", `${stext} / ${scolor}`);

  check("badge spec table matches the tested values", BADGE.danger[0] === "!!" && BADGE.warn[0] === "!" && BADGE.allowed[0] === "");
}

// ------------------------------------------------------------------ tab state
{
  reset();
  log.tabs.set(11, CLEAN);
  await listeners.updated[0](11, { status: "complete" }, { id: 11, url: CLEAN });
  const cached = await send({ type: "state", tabId: 11 });
  check("navigation fills tabState", cached?.url === CLEAN && cached?.verdict === "safe", JSON.stringify(cached));

  log.tabsGone.add(11);
  log.tabs.delete(11);
  listeners.removed[0](11);
  check("closing the tab drops its state", tabState.has(11) === false);

  const afterClose = await send({ type: "state", tabId: 11 });
  check("state of a closed tab is null", afterClose === null, JSON.stringify(afterClose));
}

{
  reset();
  // Service worker restarted: memory is empty, the tab is alive.
  log.tabs.set(12, PHISH);
  const rebuilt = await send({ type: "state", tabId: 12 });
  check("popup rescans a live tab after worker restart", rebuilt?.url === PHISH && rebuilt?.verdict === "danger", JSON.stringify(rebuilt).slice(0, 120));
  check("popup shows a probability, not 'never checked'", rebuilt?.p > 0.9, `p=${rebuilt?.p}`);
}

{
  reset();
  log.tabs.set(13, "chrome://settings");
  const skipped = await send({ type: "state", tabId: 13 });
  check("chrome:// pages are not scanned", skipped === null, JSON.stringify(skipped));

  listeners.updated[0](13, { status: "complete" }, { id: 13, url: "chrome://settings" });
  check("onUpdated ignores non-http(s)", tabState.has(13) === false);
}

{
  reset();
  const unknown = await send({ type: "nonsense" });
  check("unknown message type returns null", unknown === null);
}

{
  reset();
  log.tabs.set(14, CLEAN);
  await listeners.updated[0](14, { status: "complete" }, { id: 14, url: CLEAN });
  log.badges.length = 0;
  listeners.activated[0]({ tabId: 14 });
  await tick();
  const [text] = lastBadge();
  check("switching back to a tab restores its badge", text === "", `got "${text}"`);

  listeners.activated[0]({ tabId: 999 });
  check("activating an unknown tab does not throw", true);
}

// ------------------------------------------------------------------ no network
{
  const files = ["src/background.js", "src/content.js", "src/engine.js", "src/features.js"];
  const strip = (code) => code.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
  const bad = [];
  for (const f of files) {
    const code = strip(readFileSync(join(here, "..", f), "utf8"));
    for (const pattern of [/\bfetch\s*\(/, /XMLHttpRequest/, /importScripts/, /\beval\s*\(/, /new WebSocket/, /sendBeacon/]) {
      if (pattern.test(code)) bad.push(`${f} matches ${pattern}`);
    }
  }
  check("no networking or dynamic code in the shipped scripts", bad.length === 0, bad.join("; "));
}

// ------------------------------------------------------------------ verdict
console.log(`\n${passed} passed, ${failed} failed`);
console.log(failed === 0 ? "RULES: PASS" : "RULES: FAIL");
process.exit(failed === 0 ? 0 : 1);

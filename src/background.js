// Service worker: the only place where the model is evaluated.
// Everything here is local. There is no fetch(), no XHR, no remote code.

import { featurize } from "./features.js";
import { prepare, score, explain, verdict } from "./engine.js";

// The model is bundled at build time (train/train.py writes this file).
import { MODEL } from "./model.js";

export const prepared = prepare(MODEL);

const FEATURE_TEXT = {
  brand_lookalike: "домен маскируется под известный бренд (0→o, 1→l, 5→s)",
  brand_in_host: "в домене есть название известного сервиса",
  free_host: "сайт живёт на бесплатном хостинге (gitbook, vercel, workers.dev…)",
  has_ip_host: "вместо домена — голый IP-адрес",
  kw_login: "в адресе слова вроде login / verify / secure / wallet",
  has_punycode: "домен в punycode (xn--) — часто имитирует кириллицу",
  host_hyphens: "много дефисов в домене",
  n_subdomains: "много поддоменов",
  host_entropy: "домен похож на случайный набор символов",
  path_entropy: "случайный набор символов в пути",
  has_long_hex: "длинная hex-строка в пути",
  host_digits: "много цифр в домене",
  len_url: "очень длинный адрес",
  has_port: "нестандартный порт в адресе",
  tld_common: "необычная доменная зона",
  tld_len: "необычная доменная зона",
  double_slash_path: "двойной слэш в пути",
  n_query_params: "много параметров в адресе",
  n_special: "много служебных символов в адресе",
  n_uppercase: "заглавные буквы в адресе",
  deleet_changed: "цифры вместо букв в домене",
  query_ratio: "длинный хвост параметров",
  has_www: "нет привычного www",
  path_depth: "глубокий путь",
  longest_host_token: "очень длинный кусок домена",
  digit_ratio: "высокая доля цифр",
  url_digits: "много цифр в адресе",
  len_host: "длинный домен",
  len_path: "длинный путь",
};

export const BADGE = {
  safe: ["", "#2e7d32"],
  warn: ["!", "#f9a825"],
  danger: ["!!", "#c62828"],
  allowed: ["", "#2e7d32"],
};

export function analyzeUrl(url) {
  const x = featurize(url);
  const result = score(prepared, x);
  const items = explain(prepared, x, result, 4).map((it) => ({
    ...it,
    text: FEATURE_TEXT[it.name] || it.name,
    dir: it.weight > 0 ? "risk" : "safe",
  }));
  return { p: result.p, raw: result.raw, verdict: verdict(result.p), why: items };
}

// Page-level rules: things a URL string cannot show. They never fire on their
// own; they escalate a page that is already asking for credentials.
const RANK = { safe: 0, warn: 1, danger: 2 };

export function escalate(base, page) {
  // "This is my site, stop warning me" is an explicit user decision. It wins
  // over every rule: the whole point of the allowlist is to silence us.
  if (base.level === "allowed") return { ...base, level: "allowed", notes: [] };

  const notes = [];
  let level = base.verdict;

  if (page.hasPassword && !page.https) {
    notes.push("форма с паролем на странице без HTTPS");
    level = "danger";
  }
  if (page.brandInTitle && !page.brandInDomain) {
    notes.push(`страница называет себя «${page.brandInTitle}», но домен другой`);
    if (RANK[level] < RANK.danger) level = "warn";
  }
  if (page.hasPassword && page.hasCardField) {
    notes.push("одновременно просят пароль и данные карты");
    level = "danger";
  }
  return { ...base, level, notes };
}

export const tabState = new Map();

export function registrable(url) {
  try {
    const host = new URL(url).hostname;
    const parts = host.split(".");
    return parts.length >= 2 ? parts.slice(-2).join(".") : host;
  } catch {
    return "";
  }
}

async function allowlist() {
  const { allow = [] } = await chrome.storage.local.get("allow");
  return Array.isArray(allow) ? allow : [];
}

export async function scan(url) {
  const dom = registrable(url);
  const allow = await allowlist();
  if (dom && allow.includes(dom)) {
    return { p: 0, verdict: "safe", level: "allowed", why: [], notes: [] };
  }
  return analyzeUrl(url);
}

export function badge(tabId, level) {
  const [text, color] = BADGE[level] || ["", "#666"];
  try {
    const t = chrome.action.setBadgeText({ tabId, text });
    if (t && t.catch) t.catch(() => {});
    const c = chrome.action.setBadgeBackgroundColor({ tabId, color });
    if (c && c.catch) c.catch(() => {});
  } catch {
    /* the tab is already gone */
  }
}

async function remember(tabId, url, res) {
  const st = { url, ...res, at: Date.now() };
  tabState.set(tabId, st);
  badge(tabId, res.level || res.verdict);
  return st;
}

export function handleMessage(msg, sender) {
  return (async () => {
    if (msg.type === "credential") {
      const url = msg.url || sender.tab?.url || "";
      const res = escalate(await scan(url), msg.page || {});
      if (sender.tab?.id != null) await remember(sender.tab.id, url, res);
      return res;
    }
    if (msg.type === "state") {
      const cached = tabState.get(msg.tabId);
      if (cached) return cached;
      // The service worker may have been restarted and lost its memory.
      // The popup must not show "never checked" just because of that.
      const tab = await chrome.tabs.get(msg.tabId).catch(() => null);
      if (!tab?.url || !/^https?:/.test(tab.url)) return null;
      return remember(msg.tabId, tab.url, await scan(tab.url));
    }
    if (msg.type === "allow" || msg.type === "unallow") {
      const domain = String(msg.domain || "").toLowerCase();
      if (!domain) return { allow: await allowlist() };
      let allow = await allowlist();
      if (msg.type === "allow") {
        if (!allow.includes(domain)) allow = [...allow, domain];
      } else {
        allow = allow.filter((d) => d !== domain);
      }
      await chrome.storage.local.set({ allow });
      return { allow };
    }
    return null;
  })();
}

export function installListeners() {
  chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
    if (!info.url && info.status !== "complete") return;
    if (!tab || !tab.url || !/^https?:/.test(tab.url)) return;
    await remember(tabId, tab.url, await scan(tab.url));
  });

  chrome.tabs.onActivated.addListener(({ tabId }) => {
    const st = tabState.get(tabId);
    if (st) badge(tabId, st.level || st.verdict);
  });

  // Without this the map grows for the whole life of the browser session.
  chrome.tabs.onRemoved.addListener((tabId) => {
    tabState.delete(tabId);
  });

  chrome.runtime.onMessage.addListener((msg, sender, reply) => {
    handleMessage(msg, sender).then(reply, (e) => reply({ error: String(e) }));
    return true;
  });
}

if (typeof chrome !== "undefined" && chrome?.tabs?.onUpdated) installListeners();

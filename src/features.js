// Mirror of train/features.py. One change here must be repeated there.
// verify/parity.mjs proves the two implementations agree on 2 000 real URLs.

export const FEATURE_NAMES = [
  "len_url", "len_host", "len_path", "host_dots", "host_hyphens", "host_digits",
  "url_digits", "digit_ratio", "host_entropy", "path_entropy", "n_subdomains",
  "tld_len", "tld_common", "has_punycode", "has_port", "n_query_params",
  "n_special", "has_ip_host", "longest_host_token", "has_www", "path_depth",
  "n_uppercase", "has_long_hex", "kw_login", "double_slash_path", "free_host",
  "brand_in_host", "brand_lookalike", "deleet_changed", "query_ratio",
];

const COMMON_TLDS = new Set(("com org net ru de uk io info biz co me fr it es nl pl br in cn jp " +
  "kr tr ua kz by eu us ca au ch se no fi dk cz gr pt ro hu bg lt lv ee su tv cc xyz top site " +
  "online shop store app dev pro club").split(" "));

const BRANDS = ["google", "gmail", "youtube", "facebook", "instagram", "whatsapp", "apple",
  "icloud", "microsoft", "outlook", "office365", "paypal", "amazon", "netflix", "steam",
  "discord", "telegram", "tiktok", "binance", "coinbase", "metamask", "sberbank", "sber",
  "tinkoff", "vtb", "alfabank", "gosuslugi", "nalog", "yandex", "mail", "vk", "ok", "avito",
  "ozon", "wildberries", "dns", "mts", "megafon", "beeline", "tele2", "qiwi", "webmoney",
  "dhl", "fedex"];

const FREE_HOST_SUFFIXES = ["gitbook.io", "blogspot.com", "000webhostapp.com", "weebly.com",
  "wixsite.com", "duckdns.org", "ngrok.io", "glitch.me", "repl.co", "vercel.app", "netlify.app",
  "pages.dev", "r2.dev", "appspot.com", "web.app", "firebaseapp.com", "herokuapp.com",
  "azurewebsites.net", "trycloudflare.com", "sharepoint.com", "github.io", "gitlab.io",
  "apper.so", "kapp.so", "smart.link", "workers.dev", "s3.amazonaws.com"];

const KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm",
  "wallet", "bonus", "support", "recovery", "unlock", "billing", "invoice", "password",
  "auth", "session", "validate", "restore"];

const DELEET = { 0: "o", 1: "l", 3: "e", 5: "s", 4: "a", 7: "t" };

const isDigit = (c) => c >= "0" && c <= "9";
const isUpper = (c) => c !== c.toLowerCase() && c === c.toUpperCase();

function authority(url) {
  let rest = url.includes("://") ? url.slice(url.indexOf("://") + 3) : url;
  for (const ch of "/?#") {
    const i = rest.indexOf(ch);
    if (i !== -1) rest = rest.slice(0, i);
  }
  const at = rest.lastIndexOf("@");
  return at !== -1 ? rest.slice(at + 1) : rest;
}

function splitHost(url) {
  let host = authority(url);
  const colon = host.lastIndexOf(":");
  if (colon !== -1 && /^[0-9]+$/.test(host.slice(colon + 1))) host = host.slice(0, colon);
  return host;
}

function entropy(s) {
  if (!s) return 0;
  const counts = new Map();
  for (const c of s) counts.set(c, (counts.get(c) || 0) + 1);
  let h = 0;
  for (const v of counts.values()) {
    const p = v / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function isIp(host) {
  const parts = host.split(".");
  if (parts.length !== 4) return 0;
  for (const p of parts) {
    if (!/^[0-9]+$/.test(p) || Number(p) > 255) return 0;
  }
  return 1;
}

function hasLongHex(s) {
  let run = 0;
  for (const c of s) {
    if (/[0-9a-fA-F]/.test(c)) {
      run += 1;
      if (run >= 8) return 1;
    } else run = 0;
  }
  return 0;
}

const r6 = (x) => Math.round(x * 1e6) / 1e6;

export function featurize(url) {
  const raw = String(url).trim();
  const low = raw.toLowerCase();
  const host = splitHost(low);
  const rest = low.slice(host.length);
  const path = rest.split("?")[0].split("#")[0];
  const query = rest.includes("?") ? rest.slice(rest.indexOf("?") + 1).split("#")[0] : "";

  const tokens = host.split(".").filter(Boolean);
  const tld = tokens.length ? tokens[tokens.length - 1] : "";
  const nSub = tokens.length > 1 ? tokens.length - 2 : 0;
  const urlLen = Math.max(raw.length, 1);

  let kw = 0;
  for (const k of KEYWORDS) if (low.includes(k)) kw += 1;

  let brandInHost = 0;
  for (const b of BRANDS) if (host.includes(b)) { brandInHost = 1; break; }

  let deleeted = "";
  for (const c of host) deleeted += DELEET[c] ?? c;
  const deleetChanged = deleeted !== host ? 1 : 0;
  let lookalike = 0;
  if (deleetChanged) {
    for (const b of BRANDS) if (deleeted.includes(b)) { lookalike = 1; break; }
  }

  let freeHost = 0;
  for (const s of FREE_HOST_SUFFIXES) {
    if (host === s || host.endsWith("." + s)) { freeHost = 1; break; }
  }

  let digitsUrl = 0;
  for (const c of low) if (isDigit(c)) digitsUrl += 1;
  let digitsHost = 0;
  for (const c of host) if (isDigit(c)) digitsHost += 1;
  let upper = 0;
  for (const c of raw) if (isUpper(c)) upper += 1;
  let special = 0;
  for (const c of "@?=&#~%") special += low.split(c).length - 1;
  const qParams = query ? query.split("&").filter(Boolean).length : 0;
  const pathDepth = path.split("/").filter(Boolean).length;
  const longestToken = tokens.reduce((m, t) => Math.max(m, t.length), 0);

  return [
    raw.length,
    host.length,
    path.length,
    host.split(".").length - 1,
    host.split("-").length - 1,
    digitsHost,
    digitsUrl,
    r6(digitsUrl / urlLen),
    r6(entropy(host)),
    r6(entropy(path)),
    nSub,
    tld.length,
    COMMON_TLDS.has(tld) ? 1 : 0,
    host.includes("xn--") ? 1 : 0,
    /^.+:[0-9]+$/.test(authority(low)) ? 1 : 0,
    qParams,
    special,
    isIp(host),
    longestToken,
    host.startsWith("www.") ? 1 : 0,
    pathDepth,
    upper,
    hasLongHex(path),
    kw,
    path.includes("//") ? 1 : 0,
    freeHost,
    brandInHost,
    lookalike,
    deleetChanged,
    r6(query.length / urlLen),
  ];
}

export function registrableDomain(url) {
  const host = splitHost(String(url).trim().toLowerCase());
  const parts = host.split(".").filter(Boolean);
  return parts.length >= 2 ? parts.slice(-2).join(".") : host;
}

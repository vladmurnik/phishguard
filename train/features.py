"""URL featurizer for the PhishGuard on-device model.

IMPORTANT: this file is mirrored 1:1 by ../src/features.js.
Any change here must be repeated there, and `verify/parity.cjs` must stay green.
The featurizer never performs network calls and never resolves DNS: it looks
only at the URL string, so training and serving see exactly the same input.
"""

from __future__ import annotations

import math
import re
from collections import Counter

FEATURE_NAMES = [
    "len_url",
    "len_host",
    "len_path",
    "host_dots",
    "host_hyphens",
    "host_digits",
    "url_digits",
    "digit_ratio",
    "host_entropy",
    "path_entropy",
    "n_subdomains",
    "tld_len",
    "tld_common",
    "has_punycode",
    "has_port",
    "n_query_params",
    "n_special",
    "has_ip_host",
    "longest_host_token",
    "has_www",
    "path_depth",
    "n_uppercase",
    "has_long_hex",
    "kw_login",
    "double_slash_path",
    "free_host",
    "brand_in_host",
    "brand_lookalike",
    "deleet_changed",
    "query_ratio",
]

COMMON_TLDS = {
    "com", "org", "net", "ru", "de", "uk", "io", "info", "biz", "co", "me",
    "fr", "it", "es", "nl", "pl", "br", "in", "cn", "jp", "kr", "tr", "ua",
    "kz", "by", "eu", "us", "ca", "au", "ch", "se", "no", "fi", "dk", "cz",
    "gr", "pt", "ro", "hu", "bg", "lt", "lv", "ee", "su", "tv", "cc", "xyz",
    "top", "site", "online", "shop", "store", "app", "dev", "pro", "club",
}

# Brands that phishing kits impersonate. Kept short on purpose: the feature is
# "a brand shows up in the hostname", and every extra brand costs a substring
# scan at inference time in the browser.
BRANDS = [
    "google", "gmail", "youtube", "facebook", "instagram", "whatsapp", "apple",
    "icloud", "microsoft", "outlook", "office365", "paypal", "amazon", "netflix",
    "steam", "discord", "telegram", "tiktok", "binance", "coinbase", "metamask",
    "sberbank", "sber", "tinkoff", "vtb", "alfabank", "gosuslugi", "nalog",
    "yandex", "mail", "vk", "ok", "avito", "ozon", "wildberries", "dns",
    "mts", "megafon", "beeline", "tele2", "qiwi", "webmoney", "dhl", "fedex",
]

FREE_HOST_SUFFIXES = (
    "gitbook.io", "blogspot.com", "000webhostapp.com", "weebly.com",
    "wixsite.com", "duckdns.org", "ngrok.io", "glitch.me", "repl.co",
    "vercel.app", "netlify.app", "pages.dev", "r2.dev", "appspot.com",
    "web.app", "firebaseapp.com", "herokuapp.com", "azurewebsites.net",
    "trycloudflare.com", "sharepoint.com", "github.io", "gitlab.io",
    "apper.so", "kapp.so", "smart.link", "workers.dev", "s3.amazonaws.com",
)

KEYWORDS = (
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "wallet", "bonus", "support", "recovery", "unlock", "billing", "invoice",
    "password", "auth", "session", "validate", "restore",
)

DELEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})

# ASCII-only on purpose: str.isdigit()/isupper() are Unicode-aware and would
# disagree with the JavaScript mirror on exotic characters.
DIGITS = frozenset("0123456789")
UPPER = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def _authority(url: str) -> str:
    """userinfo and port included — needed before the port is stripped."""
    rest = url.split("://", 1)[1] if "://" in url else url
    for ch in "/?#":
        i = rest.find(ch)
        if i != -1:
            rest = rest[:i]
    at = rest.rfind("@")
    return rest[at + 1:] if at != -1 else rest


def _split_host(url: str) -> str:
    rest = url.split("://", 1)[1] if "://" in url else url
    cut = len(rest)
    for ch in "/?#":
        i = rest.find(ch)
        if i != -1 and i < cut:
            cut = i
    host = rest[:cut]
    at = host.rfind("@")
    if at != -1:
        host = host[at + 1:]
    colon = host.rfind(":")
    if colon != -1 and host[colon + 1:].isdigit():
        host = host[:colon]
    return host


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _is_ip(host: str) -> int:
    parts = host.split(".")
    if len(parts) != 4:
        return 0
    for p in parts:
        if not p or any(c not in DIGITS for c in p) or not 0 <= int(p) <= 255:
            return 0
    return 1


def _has_long_hex(s: str) -> int:
    run = 0
    for ch in s:
        if ch in "0123456789abcdefABCDEF":
            run += 1
            if run >= 8:
                return 1
        else:
            run = 0
    return 0


def featurize(url: str) -> list[float]:
    raw = url.strip()
    low = raw.lower()
    host = _split_host(low)
    rest = low[len(host):]
    path = rest.split("?", 1)[0].split("#", 1)[0]
    query = rest.split("?", 1)[1].split("#", 1)[0] if "?" in rest else ""

    tokens = [t for t in host.split(".") if t]
    tld = tokens[-1] if tokens else ""
    n_sub = max(len(tokens) - 2, 0) if len(tokens) > 1 else 0
    url_len = max(len(raw), 1)

    kw = sum(1 for k in KEYWORDS if k in low)
    brand_in_host = 1 if any(b in host for b in BRANDS) else 0
    deleeted = host.translate(DELEET)
    deleet_changed = 1 if deleeted != host else 0
    lookalike = 0
    if deleet_changed and any(b in deleeted for b in BRANDS):
        # A brand appears only after undoing leetspeak -> classic typo-squat.
        lookalike = 1

    free_host = 1 if any(host == s or host.endswith("." + s) for s in FREE_HOST_SUFFIXES) else 0

    return [
        float(len(raw)),
        float(len(host)),
        float(len(path)),
        float(host.count(".")),
        float(host.count("-")),
        float(sum(c in DIGITS for c in host)),
        float(sum(c in DIGITS for c in low)),
        round(sum(c in DIGITS for c in low) / url_len, 6),
        round(_entropy(host), 6),
        round(_entropy(path), 6),
        float(n_sub),
        float(len(tld)),
        float(tld in COMMON_TLDS),
        float("xn--" in host),
        float(re.match(r".+:\d+$", _authority(low)) is not None),
        float(len([p for p in query.split("&") if p])),
        float(sum(low.count(c) for c in "@?=&#~%")),
        float(_is_ip(host)),
        float(max((len(t) for t in tokens), default=0)),
        float(host.startswith("www.")),
        float(len([p for p in path.split("/") if p])),
        float(sum(c in UPPER for c in raw)),
        float(_has_long_hex(path)),
        float(kw),
        float("//" in path),
        float(free_host),
        float(brand_in_host),
        float(lookalike),
        float(deleet_changed),
        round(len(query) / url_len, 6),
    ]


def registrable_domain(url: str) -> str:
    """Coarse eTLD+1 approximation, used only for the grouped train/test split."""
    host = _split_host(url.strip().lower())
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

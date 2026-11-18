// Content script. Its only job is to notice the risky moment and to show a
// warning. It never decides anything: the score comes from the service worker.
//
// Trigger rule (this is the product decision): we do not interrupt ordinary
// reading. We speak up when the page is about to receive your credentials.

(() => {
  const BRANDS = ["google", "gmail", "youtube", "facebook", "instagram", "whatsapp",
    "apple", "icloud", "microsoft", "outlook", "office365", "paypal", "amazon", "netflix",
    "steam", "discord", "telegram", "tiktok", "binance", "coinbase", "metamask",
    "sberbank", "sber", "tinkoff", "vtb", "alfabank", "gosuslugi", "nalog", "yandex",
    "mail", "vk", "avito", "ozon", "wildberries", "qiwi", "webmoney", "mts", "megafon"];

  if (window.__phishguardLoaded) return;
  window.__phishguardLoaded = true;

  const dismissed = new Set();
  let shown = false;

  function pageSignals() {
    const pw = document.querySelectorAll('input[type="password"]');
    const card = document.querySelector(
      'input[autocomplete*="cc-"], input[name*="card" i], input[name*="cvc" i], input[id*="card" i]'
    );
    const title = (document.title || "").toLowerCase();
    const host = location.hostname.toLowerCase();
    const brand = BRANDS.find((b) => title.includes(b));
    return {
      https: location.protocol === "https:",
      hasPassword: pw.length > 0,
      passwordCount: pw.length,
      hasCardField: Boolean(card),
      brandInTitle: brand || "",
      brandInDomain: BRANDS.some((b) => host.includes(b)),
    };
  }

  function banner(res) {
    const danger = res.level === "danger";
    const host = document.createElement("phishguard-banner");
    const root = host.attachShadow({ mode: "open" });
    const reasons = (res.why || [])
      .filter((w) => w.dir === "risk")
      .slice(0, 3)
      .map((w) => `<li>${w.text}</li>`)
      .join("");
    const extra = (res.notes || []).map((n) => `<li>${n}</li>`).join("");
    root.innerHTML = `
      <style>
        :host { all: initial; }
        .box {
          position: fixed; top: 12px; left: 50%; transform: translateX(-50%);
          width: min(520px, 92vw); z-index: 2147483647;
          font: 14px/1.45 -apple-system, "Segoe UI", Roboto, sans-serif;
          background: ${danger ? "#7f1d1d" : "#78350f"}; color: #fff;
          border-radius: 12px; padding: 14px 16px 12px;
          box-shadow: 0 18px 48px rgba(0,0,0,.45);
          border: 1px solid rgba(255,255,255,.18);
        }
        .row { display: flex; gap: 10px; align-items: flex-start; }
        .score {
          flex: 0 0 auto; font-weight: 700; font-size: 22px;
          background: rgba(255,255,255,.12); border-radius: 8px;
          padding: 2px 10px; letter-spacing: -.5px;
        }
        h1 { margin: 0 0 4px; font-size: 15px; font-weight: 700; }
        p { margin: 0; opacity: .85; font-size: 13px; }
        ul { margin: 8px 0 0; padding-left: 18px; font-size: 13px; opacity: .92; }
        li { margin: 2px 0; }
        .acts { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
        button {
          font: inherit; font-size: 13px; cursor: pointer; border-radius: 8px;
          padding: 6px 12px; border: 1px solid rgba(255,255,255,.35);
          background: transparent; color: #fff;
        }
        button.primary { background: #fff; color: #111; border-color: #fff; font-weight: 600; }
        button:hover { opacity: .9; }
        .url { font-family: ui-monospace, Consolas, monospace; font-size: 12px; opacity: .7;
               word-break: break-all; margin-top: 6px; }
      </style>
      <div class="box" role="alert">
        <div class="row">
          <div class="score">${Math.round(res.p * 100)}%</div>
          <div style="flex:1">
            <h1>${danger ? "Похоже на поддельный сайт" : "Сайт выглядит подозрительно"}</h1>
            <p>Не вводите пароль, пока не проверите адрес. Модель работает на вашем
               компьютере, никуда ничего не отправляется.</p>
            <ul>${reasons}${extra}</ul>
            <div class="url">${location.hostname}</div>
          </div>
        </div>
        <div class="acts">
          <button class="primary" id="close">Закрыть</button>
          <button id="allow">Это мой сайт, больше не предупреждать</button>
        </div>
      </div>`;
    root.getElementById("close").onclick = () => host.remove();
    root.getElementById("allow").onclick = () => {
      chrome.runtime.sendMessage({ type: "allow", domain: registrable(location.hostname) });
      host.remove();
    };
    document.documentElement.appendChild(host);
    setTimeout(() => host.remove(), 30000);
  }

  function registrable(host) {
    const p = host.split(".");
    return p.length >= 2 ? p.slice(-2).join(".") : host;
  }

  async function check() {
    if (shown || dismissed.has(location.href)) return;
    const signals = pageSignals();
    if (!signals.hasPassword) return;
    const res = await chrome.runtime.sendMessage({
      type: "credential",
      url: location.href,
      page: signals,
    });
    if (!res || !res.level) return;
    if (res.level === "safe" || res.level === "allowed") return;
    shown = true;
    dismissed.add(location.href);
    banner(res);
  }

  document.addEventListener("focusin", (e) => {
    const t = e.target;
    if (t && t.tagName === "INPUT" && (t.type === "password" || /pass/i.test(t.name || ""))) check();
  }, true);

  document.addEventListener("submit", (e) => {
    const form = e.target;
    if (form && form.querySelector && form.querySelector('input[type="password"]')) check();
  }, true);

  // A page that shows a password box right away is checked once on load too.
  setTimeout(check, 1200);
})();

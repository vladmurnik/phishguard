const $ = (id) => document.getElementById(id);

function registrable(host) {
  const p = (host || "").split(".");
  return p.length >= 2 ? p.slice(-2).join(".") : host || "";
}

async function main() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let host = "";
  try {
    host = new URL(tab.url).hostname;
  } catch {
    $("host").textContent = "эта страница не проверяется";
    $("pct").textContent = "—";
    $("tag").textContent = "не http(s)";
    $("meta").textContent = "Расширение работает только на сайтах";
    return;
  }
  const st = await chrome.runtime.sendMessage({ type: "state", tabId: tab.id });
  const dom = registrable(host);
  $("host").textContent = host;

  const { allow = [] } = await chrome.storage.local.get("allow");
  const allowed = allow.includes(dom);

  if (!st) {
    $("pct").textContent = "—";
    $("tag").textContent = "не проверялось";
    $("meta").textContent = "Откройте страницу заново";
    return;
  }

  const p = st.p ?? 0;
  const level = allowed ? "safe" : st.level || st.verdict;
  $("pct").textContent = `${Math.round(p * 100)}%`;
  const tag = $("tag");
  tag.textContent = allowed ? "разрешён вами"
    : level === "danger" ? "опасно" : level === "warn" ? "подозрительно" : "похоже на нормальный";
  tag.className = `tag ${level === "danger" ? "danger" : level === "warn" ? "warn" : "safe"}`;

  const fill = $("fill");
  fill.style.width = `${Math.max(2, Math.round(p * 100))}%`;
  fill.style.background = level === "danger" ? "#e05a5a" : level === "warn" ? "#e0b45a" : "#5ac07a";

  const why = $("why");
  why.innerHTML = "";
  for (const w of (st.why || []).slice(0, 4)) {
    const li = document.createElement("li");
    li.innerHTML = `<span class="g">${w.dir === "risk" ? "↑" : "↓"} ${w.text}</span>
                    <span class="w">${w.weight.toFixed(2)}</span>`;
    why.appendChild(li);
  }
  for (const n of st.notes || []) {
    const li = document.createElement("li");
    li.innerHTML = `<span class="g">↑ ${n}</span>`;
    why.appendChild(li);
  }

  $("meta").textContent = `проверено ${new Date(st.at).toLocaleTimeString()}`;
  const btn = $("toggle");
  btn.textContent = allowed ? "Убрать из разрешённых" : "Разрешить этот домен";
  btn.onclick = async () => {
    await chrome.runtime.sendMessage({ type: allowed ? "unallow" : "allow", domain: dom });
    location.reload();
  };
}

main();

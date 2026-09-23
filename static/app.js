const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

let currentId = null;
let lastLogId = 0;
let category = "";
let pollTimer = null;
let findingsCache = [];
let findingsTick = 0;

const CATS = ["subs", "probe", "ports", "dirs", "source", "nuclei"];
const CAT_LABEL = {
  subs: "Subdomain",
  probe: "Live",
  ports: "Port",
  dirs: "Directory",
  source: "Source",
  nuclei: "Nuclei",
};

async function api(path, opts) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const j = await res.json();
      msg = j.detail || JSON.stringify(j);
    } catch (_) {}
    throw new Error(msg);
  }
  if (res.status === 204) return null;
  return res.json();
}

async function loadTools() {
  const tools = await api("/api/tools");
  $("#tools").innerHTML = Object.entries(tools)
    .map(([k, v]) => `<span class="${v ? "on" : "off"}">${k}${v ? "" : " ✕"}</span>`)
    .join("");
}

async function loadScans() {
  const scans = await api("/api/scans");
  $("#scan-list").innerHTML = scans
    .map(
      (s) => `
      <button class="scan-item ${s.id === currentId ? "active" : ""}" data-id="${s.id}">
        <b>${esc(s.target)}</b>
        <small>#${s.id} · ${s.status} · ${s.reviewed}/${s.findings} baxılıb</small>
      </button>`
    )
    .join("") || `<p class="muted">Hələ scan yoxdur</p>`;
  $$("#scan-list .scan-item").forEach((b) =>
    b.addEventListener("click", () => openScan(Number(b.dataset.id)))
  );
}

async function openScan(id) {
  currentId = id;
  lastLogId = 0;
  findingsCache = [];
  window.__pcPaint = "";
  $("#logs").textContent = "";
  $("#dl-txt").href = `/api/scans/${id}/export.txt`;
  $("#dl-csv").href = `/api/scans/${id}/export.csv`;
  await refreshScan();
  await loadScans();
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(refreshScan, 2000);
}

async function refreshScan() {
  if (!currentId) return;
  const scan = await api(`/api/scans/${currentId}`);
  $("#scan-title").textContent = scan.target;
  $("#scan-meta").textContent = `#${scan.id} · ${scan.status} · mərhələlər: ${scan.stages}`;
  const counts = scan.counts || {};
  $("#stats").innerHTML = [
    ["status", scan.status],
    ["tapıntı", scan.findings],
    ["baxılıb", scan.reviewed],
    ...CATS.map((c) => [CAT_LABEL[c], counts[c] || 0]),
  ]
    .slice(0, 6)
    .map(([k, v]) => `<div class="stat"><em>${k}</em><strong>${v}</strong></div>`)
    .join("");

  const stages = scan.stages.split(",");
  $("#progress-pills").innerHTML = stages
    .map((s) => {
      const on = scan.current_stage === s || scan.status === "done";
      return `<b class="${scan.current_stage === s ? "run" : ""}">${s}</b>`;
    })
    .join("");

  const logs = await api(`/api/scans/${currentId}/logs?after=${lastLogId}`);
  if (logs.length) {
    lastLogId = logs[logs.length - 1].id;
    $("#logs").textContent += logs.map((l) => `[${l.level}] ${l.message}`).join("\n") + "\n";
    $("#logs").scrollTop = $("#logs").scrollHeight;
  }
  await loadFindings(true);
  if (scan.status === "done" || scan.status === "error") {
    await loadScans();
  }
}

async function loadFindings(fromServer = false) {
  if (!currentId) return;
  if (fromServer) {
    const tick = ++findingsTick;
    const items = await api(`/api/scans/${currentId}/findings`);
    if (tick !== findingsTick) return;
    findingsCache = items;
  }
  let items = findingsCache.slice();
  const qtext = $("#filter").value.trim().toLowerCase();
  const onlyOpen = $("#only-open").checked;
  items = items.filter((it) => {
    if (category && it.category !== category) return false;
    if (onlyOpen && it.reviewed) return false;
    if (!qtext) return true;
    return (it.title + " " + (it.detail || "") + " " + (it.note || "") + " " + (it.ip || "")).toLowerCase().includes(qtext);
  });
  $("#count-label").textContent = `${items.length} sətir`;
  const paintKey = items.map((i) => `${i.id}:${i.screenshot || ""}:${i.reviewed || 0}:${category}`).join("|");
  if (window.__pcPaint === paintKey) {
    renderNotesTable();
    return;
  }
  window.__pcPaint = paintKey;
  const visual = !category || category === "subs" || category === "probe";
  if (visual) {
    $("#findings").className = "cards";
    $("#findings").innerHTML = items
      .map((it) => {
        const url = it.url || guessFrontUrl(it.title);
        const shot = it.screenshot ? `/api/findings/${it.id}/shot` : "";
        return `
        <article class="card-item" data-id="${it.id}" data-url="${escAttr(url)}" data-title="${escAttr(it.title)}" data-ip="${escAttr(it.ip || "")}" data-shot="${shot}">
          ${shot ? `<img class="thumb" src="${shot}" alt="" />` : `<div class="thumb empty">görüntü yoxdur</div>`}
          <div class="card-body">
            <label class="chk"><input type="checkbox" class="rev" ${it.reviewed ? "checked" : ""} /> baxdım</label>
            <div><a class="open" href="${escAttr(url)}" target="_blank" rel="noopener">${esc(it.title)}</a></div>
            <div class="ip">${esc(it.ip || "IP yoxdur")}</div>
            <input class="note" placeholder="qeyd yaz..." value="${escAttr(it.note || "")}" />
          </div>
        </article>`;
      })
      .join("") || `<p class="muted">Tapıntı yoxdur.</p>`;
  } else {
    $("#findings").className = "list";
    $("#findings").innerHTML = items
      .map(
        (it) => `
        <article class="row" data-id="${it.id}">
          <input type="checkbox" class="rev" ${it.reviewed ? "checked" : ""} title="Baxdım" />
          <span class="sev ${esc(it.severity || "info")}">${esc(it.severity || "info")}</span>
          <div>
            <div class="title">${esc(it.title)}</div>
            ${it.detail && it.detail !== it.title ? `<div class="detail">${esc(it.detail)}</div>` : ""}
            <input class="note" placeholder="qeyd yaz..." value="${escAttr(it.note || "")}" />
          </div>
          <span class="muted">${CAT_LABEL[it.category] || it.category}</span>
        </article>`
      )
      .join("") || `<p class="muted">Bu kateqoriyada tapıntı yoxdur.</p>`;
  }

  $$("#findings .rev").forEach((box) => {
    box.addEventListener("change", async () => {
      const id = box.closest(".row, .card-item").dataset.id;
      await api(`/api/findings/${id}/review`, {
        method: "POST",
        body: JSON.stringify({ reviewed: box.checked }),
      });
      loadScans();
    });
  });
  $$("#findings .card-item").forEach((card) => {
    card.addEventListener("click", (ev) => {
      if (ev.target.closest("a, input, label")) return;
      openDrawer(card.dataset);
    });
  });
  $$("#findings .note").forEach((inp) => {
    inp.addEventListener("change", async () => {
      const wrap = inp.closest(".row, .card-item");
      const id = wrap.dataset.id;
      await api(`/api/findings/${id}/note`, {
        method: "POST",
        body: JSON.stringify({ note: inp.value }),
      });
      const row = findingsCache.find((x) => String(x.id) === String(id));
      if (row) row.note = inp.value;
      renderNotesTable();
    });
  });
  renderNotesTable();
}

function notesRows() {
  return findingsCache.filter(
    (it) =>
      (it.category === "subs" || it.category === "probe") &&
      String(it.note || "").trim()
  );
}

function mdCell(s) {
  return String(s || "").replaceAll("|", "\\|").replaceAll("\n", " ").trim();
}

function notesMarkdown() {
  const rows = notesRows();
  const lines = ["| Host | URL | Qeyd |", "| ---- | --- | ---- |"];
  for (const it of rows) {
    const host = (it.title || "").split(/\s+/)[0].replace(/^https?:\/\//, "").split("/")[0];
    const url = it.url || guessFrontUrl(it.title);
    lines.push(`| ${mdCell(host)} | ${mdCell(url)} | ${mdCell(it.note)} |`);
  }
  return lines.join("\n");
}

function renderNotesTable() {
  const rows = notesRows();
  const empty = $("#notes-empty");
  const tb = $("#notes-table tbody");
  if (!tb) return;
  if (!rows.length) {
    empty.hidden = false;
    tb.innerHTML = "";
    return;
  }
  empty.hidden = true;
  tb.innerHTML = rows
    .map((it) => {
      const host = (it.title || "").split(/\s+/)[0].replace(/^https?:\/\//, "").split("/")[0];
      const url = it.url || guessFrontUrl(it.title);
      return `<tr><td>${esc(host)}</td><td>${esc(url)}</td><td>${esc(it.note)}</td></tr>`;
    })
    .join("");
}

$("#scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const stages = fd.getAll("stage");
  const btn = $("#start-btn");
  btn.disabled = true;
  try {
    const created = await api("/api/scans", {
      method: "POST",
      body: JSON.stringify({
        target: fd.get("target"),
        stages,
        wordlist: fd.get("wordlist") || null,
        authorized: fd.get("authorized") === "on",
      }),
    });
    await loadScans();
    openScan(created.id);
  } catch (err) {
    alert(err.message);
  } finally {
    btn.disabled = false;
  }
});

$$("#tabs button").forEach((b) => {
  b.addEventListener("click", () => {
    $$("#tabs button").forEach((x) => x.classList.remove("on"));
    b.classList.add("on");
    category = b.dataset.cat || "";
    loadFindings(false);
  });
});
$("#demo-btn").addEventListener("click", async () => {
  try {
    const created = await api("/api/demo", { method: "POST" });
    await loadScans();
    openScan(created.id);
  } catch (err) {
    alert(err.message);
  }
});
$("#copy-notes").addEventListener("click", async () => {
  const md = notesMarkdown();
  try {
    await navigator.clipboard.writeText(md);
    $("#copy-notes").textContent = "Kopyalandı";
    setTimeout(() => { $("#copy-notes").textContent = "Cədvəli kopyala"; }, 1200);
  } catch (_) {
    prompt("Kopyala:", md);
  }
});
$("#filter").addEventListener("input", () => loadFindings(false));
$("#only-open").addEventListener("change", () => loadFindings(false));

function guessFrontUrl(title) {
  const t = String(title || "").trim().split(/\s+/)[0];
  if (t.startsWith("http://") || t.startsWith("https://")) return t;
  return t ? `https://${t}` : "#";
}

function openDrawer(ds) {
  $("#drawer-title").textContent = ds.title || "";
  $("#drawer-meta").textContent = ds.ip ? `IP: ${ds.ip}` : "IP tapılmadı";
  $("#drawer-link").href = ds.url || "#";
  const img = $("#drawer-img");
  if (ds.shot) {
    img.hidden = false;
    img.src = ds.shot;
  } else {
    img.hidden = true;
    img.removeAttribute("src");
  }
  $("#drawer").hidden = false;
}
$("#drawer-close").addEventListener("click", () => {
  $("#drawer").hidden = true;
});
$("#drawer").addEventListener("click", (e) => {
  if (e.target.id === "drawer") $("#drawer").hidden = true;
});

function esc(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}
function escAttr(s) {
  return esc(s).replaceAll('"', "&quot;");
}

loadTools();
loadScans();

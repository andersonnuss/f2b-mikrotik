"use strict";

// ---------------------------------------------------------------------------
// utilitarios
// ---------------------------------------------------------------------------
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: {}, credentials: "same-origin" };
  if (init.method !== "GET") {
    init.headers["Content-Type"] = "application/json";
    init.headers["X-Requested-With"] = "f2b-web";
    init.body = JSON.stringify(opts.body || {});
  }
  // location.origin nao inclui usuario:senha (fetch recusa URLs com credenciais embutidas)
  const res = await fetch(new URL(path, location.origin), init);
  let data = null;
  try { data = await res.json(); } catch (_) { /* resposta sem JSON */ }
  if (!res.ok) throw new Error((data && data.error) || `${res.status} ${res.statusText}`);
  return data;
}

const STATE_VIEW = {
  "agente": ["st-ok", "bloqueado"],
  "manual": ["st-info", "manual"],
  "faltando": ["st-bad", "faltando"],
  "a remover": ["st-warn", "a remover"],
  "desativado": ["st-warn", "entrada desativada"],
  "?": ["st-muted", "?"],
  "": ["st-muted", "—"],
};
const stateBadge = (s) => {
  const [cls, label] = STATE_VIEW[s] || ["st-muted", s];
  return `<span class="st ${cls}">${esc(label)}</span>`;
};

const STATUS_VIEW = { online: "ok", offline: "bad", desabilitado: "warn" };
const statusPill = (s) => `<span class="pill ${STATUS_VIEW[s] || ""}">${esc(s)}</span>`;

const REL_TEXT = { igual: "", dentro: "consultado está dentro de", contem: "rede consultada contém" };
const relText = (m) => (m.relation === "igual" ? esc(m.entry) : `${REL_TEXT[m.relation]} <span class="mono">${esc(m.entry)}</span>`);

let overview = null;
let routersCache = [];

// ---------------------------------------------------------------------------
// abas
// ---------------------------------------------------------------------------
function showTab(name) {
  $$(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  $$(".tab").forEach((t) => t.classList.toggle("active", t.id === `tab-${name}`));
  if (name === "log") loadLog();
  try { localStorage.setItem("f2b-tab", name); } catch (_) { /* sem storage */ }
}
$$(".tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));

// ---------------------------------------------------------------------------
// visao geral
// ---------------------------------------------------------------------------
async function loadOverview() {
  const btn = $("#refresh");
  btn.disabled = true;
  btn.textContent = "Atualizando…";
  try {
    overview = await api("/api/overview");
    $("#overview-error").innerHTML = "";
    renderOverview();
    renderEntries();
    renderRouters();
  } catch (e) {
    $("#overview-error").innerHTML = `<div class="alert">Falha ao carregar: ${esc(e.message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Atualizar";
  }
}

function renderOverview() {
  const o = overview;
  $("#version").textContent = `v${o.version}`;
  $("#updated").textContent = `atualizado ${o.generated_at}`;
  const svc = o.agent_service;
  const svcCls = svc === "active" ? "ok" : (svc === "desconhecido" ? "" : "bad");
  $("#agent-status").className = `pill ${svcCls}`;
  $("#agent-status").textContent = `agente: ${svc === "active" ? "rodando" : svc}`;

  const online = o.routers.filter((r) => r.status === "online").length;
  const enabled = o.routers.filter((r) => r.enabled).length;
  const banned = new Set();
  o.fail2ban.jails.forEach((j) => j.ips.forEach((ip) => banned.add(ip)));
  const pending = o.routers.reduce((n, r) => n + (r.missing || []).length + (r.extra || []).length, 0);
  $("#stats").innerHTML = [
    [o.desired_count, "a bloquear (fail2ban + blacklist)"],
    [o.fail2ban.ok ? banned.size : "erro", "IPs banidos no fail2ban"],
    [o.blacklist.ok ? o.blacklist.entries.length : "erro", "entradas na blacklist"],
    [`${online}/${enabled}`, "roteadores online"],
    [pending, "divergências (faltando + a remover)"],
  ].map(([v, l]) => `<div class="stat"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");

  $("#router-cards").innerHTML = o.routers.map((r) => {
    const info = r.status === "online"
      ? `<dl>
           <dt>modelo</dt><dd>${esc(r.board)} · RouterOS ${esc(r.version)}</dd>
           <dt>identity</dt><dd>${esc(r.identity)}</dd>
           <dt>uptime</dt><dd>${r.uptime ? `${esc(r.uptime)} · ` : ""}resposta em ${esc(r.latency_ms)} ms</dd>
           <dt>na lista</dt><dd>${r.managed_count} do agente · ${r.other_count} manual</dd>
           <dt>sincronia</dt><dd>${r.missing.length || r.extra.length
              ? [r.missing.length ? `<span class="st st-bad">${r.missing.length} faltando</span>` : "",
                 r.extra.length ? `<span class="st st-warn">${r.extra.length} a remover</span>` : ""].join(" ")
              : '<span class="st st-ok">em dia</span>'}</dd>
         </dl>`
      : (r.error ? `<div class="alert">${esc(r.error)}</div>` : "");
    return `<div class="router-card ${r.status === "offline" ? "offline" : ""}">
      <header><strong>${esc(r.name)}</strong>${r.primary ? '<span class="pill">principal</span>' : ""}${statusPill(r.status)}</header>
      <div class="muted mono small">${esc(r.host)}:${esc(r.port)}${r.use_ssl ? " · SSL" : ""}</div>
      ${info}
    </div>`;
  }).join("");

  const f = o.fail2ban;
  $("#f2b-box").innerHTML = !f.ok
    ? `<div class="alert">${esc(f.error)}</div>`
    : (f.jails.length ? `<div class="jail-list">${f.jails.map((j) => `
        <div class="jail-head"><strong>${esc(j.name)}</strong>
          <span class="count">${j.ips.length} banido(s)</span>
          ${j.replicated ? "" : '<span class="pill warn">não replicada</span>'}</div>`).join("")}</div>`
      : '<span class="muted">nenhuma jail ativa</span>');

  const b = o.blacklist;
  $("#bl-form").hidden = !b.file;
  $("#bl-box").innerHTML = !b.file ? '<span class="muted">desativada no config.ini ([blacklist] file)</span>'
    : !b.ok ? `<div class="alert">${esc(b.error)}</div>`
      : (b.items.length ? `<div class="bl-list">${b.items.map((it) => `
          <div class="bl-item">
            <button type="button" class="link mono" data-check="${esc(it.entry)}">${esc(it.entry)}</button>
            <span class="muted small bl-comment">${esc(it.comment)}</span>
            ${it.ignored ? `<span class="pill warn" title="o agente ignora esta linha">ignorado: ${esc(it.ignored)}</span>` : ""}
            <button type="button" class="btn small" data-act="bl-del" data-entry="${esc(it.entry)}" title="remover da blacklist">Remover</button>
          </div>`).join("")}</div>` : '<p class="muted small">vazia</p>')
        + `<div class="muted small mono mt">${esc(b.file)}</div>`;
  $("#wl-box").innerHTML = o.whitelist.length
    ? `<div class="chips">${o.whitelist.map(chip).join("")}</div>` : '<span class="muted">vazia</span>';
}

const chip = (v) => `<button type="button" class="chip" data-check="${esc(v)}">${esc(v)}</button>`;

// clique em qualquer IP/rede -> consulta
document.addEventListener("click", (ev) => {
  const el = ev.target.closest("[data-check]");
  if (!el) return;
  $("#check-ip").value = el.dataset.check;
  runCheck();
  window.scrollTo({ top: 0, behavior: "smooth" });
});

// ---------------------------------------------------------------------------
// tabela de bloqueios
// ---------------------------------------------------------------------------
function renderEntries() {
  if (!overview) return;
  const routers = overview.routers;
  const filter = $("#entries-filter").value.trim().toLowerCase();
  const source = $("#entries-source").value;
  const onlyDiff = $("#entries-diff").checked;

  const rows = overview.entries.filter((e) => {
    if (source === "fail2ban" && !e.jails.length) return false;
    if (source === "blacklist" && !e.blacklist) return false;
    if (source === "router" && e.sources.length) return false;
    if (onlyDiff && !Object.values(e.routers).some((s) => s === "faltando" || s === "a remover")) return false;
    if (filter && !(e.key.toLowerCase().includes(filter) || e.sources.join(" ").toLowerCase().includes(filter))) return false;
    return true;
  });

  $("#count-entries").textContent = overview.entries.length;
  $("#entries-info").textContent = `${rows.length} de ${overview.entries.length}`;
  const head = `<thead><tr><th>IP / rede</th><th>fail2ban</th><th>blacklist</th>
    ${routers.map((r) => `<th class="center">${esc(r.name)}</th>`).join("")}<th></th></tr></thead>`;
  const body = rows.length ? rows.slice(0, 3000).map((e) => `<tr>
      <td><button type="button" class="link mono" data-check="${esc(e.key)}">${esc(e.key)}</button>
        ${e.note ? `<div class="muted small">${esc(e.note)}</div>` : ""}
        ${!e.sources.length ? '<div class="muted small">só no roteador</div>' : ""}</td>
      <td>${e.jails.map((j) => `<span class="pill">${esc(j)}</span>`).join(" ")}</td>
      <td>${e.blacklist ? '<span class="pill info">sim</span>' : ""}</td>
      ${routers.map((r) => `<td class="center">${stateBadge(e.routers[r.id])}</td>`).join("")}
      <td><div class="actions">${rowActions(e)}</div></td>
    </tr>`).join("")
    : `<tr><td colspan="${routers.length + 4}" class="empty">nada encontrado</td></tr>`;
  $("#entries-table").innerHTML = head + `<tbody>${body}</tbody>`;
}

function rowActions(e) {
  const out = [];
  if (e.jails.length) out.push(`<button type="button" class="btn small" data-act="unban" data-ip="${esc(e.key)}">Desbanir</button>`);
  if (e.blacklist) out.push(`<button type="button" class="btn small" data-act="bl-del" data-entry="${esc(e.key)}">Tirar da blacklist</button>`);
  else if (!e.whitelisted) out.push(`<button type="button" class="btn small" data-act="bl-add" data-entry="${esc(e.key)}">+ Blacklist</button>`);
  return out.join("");
}

// ---------------------------------------------------------------------------
// acoes: desbanir e blacklist
// ---------------------------------------------------------------------------
let toastTimer = null;
function toast(msg, kind = "ok") {
  const el = $("#toast");
  el.textContent = msg;
  el.className = `toast show ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = "toast"; }, 6000);
}

// o agente replica em ~2 s: recarrega ja (blacklist/fail2ban) e de novo depois (roteadores)
function refreshSoon() {
  loadOverview();
  setTimeout(() => {
    loadOverview();
    if ($("#check-result").innerHTML.trim()) runCheck();
  }, 3500);
}

async function doUnban(ip) {
  const e = overview && overview.entries.find((x) => x.key === ip);
  let msg = `Desbanir ${ip} no fail2ban${e && e.jails.length ? ` (jail: ${e.jails.join(", ")})` : ""}?\n\n`
    + "O agente libera o IP nos MikroTiks em cerca de 2 segundos.";
  if (e && e.blacklist) msg += `\n\nAtenção: ${ip} também está na blacklist e continuará bloqueado nos roteadores.`;
  if (!confirm(msg)) return;
  const r = await api("/api/unban", { method: "POST", body: { ip } });
  toast(r.in_blacklist
    ? `${r.ip} desbanido de ${r.jails.join(", ")}, mas continua bloqueado pela blacklist.`
    : `${r.ip} desbanido de ${r.jails.join(", ")}. O agente está liberando nos MikroTiks…`, r.in_blacklist ? "warn" : "ok");
  refreshSoon();
}

async function doBlacklistAdd(entry, comment) {
  if (comment === undefined) {
    comment = prompt(`Incluir ${entry} na blacklist?\nEle será bloqueado em todos os MikroTiks.\n\nMotivo (opcional):`, "");
    if (comment === null) return;
  }
  const r = await api("/api/blacklist", { method: "POST", body: { entry, comment } });
  toast(`${r.entry} incluído na blacklist. O agente está bloqueando nos MikroTiks…`);
  refreshSoon();
  return r;
}

async function doBlacklistRemove(entry) {
  const e = overview && overview.entries.find((x) => x.key === entry);
  let msg = `Remover ${entry} da blacklist?\n\nO agente libera nos MikroTiks em cerca de 2 segundos.`;
  if (e && e.jails.length) msg += `\n\nAtenção: ${entry} também está banido no fail2ban (${e.jails.join(", ")}) e continuará bloqueado até o ban expirar ou ser desfeito.`;
  if (!confirm(msg)) return;
  const r = await api("/api/blacklist", { method: "DELETE", body: { entry } });
  toast(`${r.entry} removido da blacklist.`);
  refreshSoon();
}

document.addEventListener("click", async (ev) => {
  const btn = ev.target.closest("[data-act]");
  if (!btn || !["unban", "bl-add", "bl-del"].includes(btn.dataset.act)) return;
  btn.disabled = true;
  try {
    if (btn.dataset.act === "unban") await doUnban(btn.dataset.ip);
    if (btn.dataset.act === "bl-add") await doBlacklistAdd(btn.dataset.entry);
    if (btn.dataset.act === "bl-del") await doBlacklistRemove(btn.dataset.entry);
  } catch (e) {
    toast(e.message, "bad");
  } finally {
    btn.disabled = false;
  }
});

$("#bl-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const fe = ev.target.elements;
  try {
    await doBlacklistAdd(fe.namedItem("entry").value.trim(), fe.namedItem("comment").value.trim());
    ev.target.reset();
  } catch (e) {
    toast(e.message, "bad");
  }
});
["#entries-filter", "#entries-source", "#entries-diff"].forEach((s) => $(s).addEventListener("input", renderEntries));

// ---------------------------------------------------------------------------
// consulta de IP
// ---------------------------------------------------------------------------
async function runCheck() {
  const ip = $("#check-ip").value.trim();
  const box = $("#check-result");
  if (!ip) { box.innerHTML = ""; return; }
  box.innerHTML = '<p class="muted">Consultando fail2ban e roteadores…</p>';
  try {
    renderCheck(await api(`/api/check?ip=${encodeURIComponent(ip)}`));
  } catch (e) {
    box.innerHTML = `<div class="alert">${esc(e.message)}</div>`;
  }
}

function renderCheck(c) {
  const online = c.routers.filter((r) => r.status === "online");
  const blocked = online.filter((r) => r.blocked);
  const expected = c.desired.some((d) => d.relation !== "contem");
  let cls = "free";
  let title = `${esc(c.query)} não está bloqueado em nenhum MikroTik`;
  if (blocked.length && blocked.length === online.length) {
    cls = "blocked";
    title = `${esc(c.query)} está BLOQUEADO em ${online.length === 1 ? "o roteador" : `todos os ${online.length} roteadores`} online`;
  } else if (blocked.length) {
    cls = "partial";
    title = `${esc(c.query)} está bloqueado em ${blocked.length} de ${online.length} roteadores online`;
  } else if (expected && online.length) {
    cls = "partial";
    title = `${esc(c.query)} deveria estar bloqueado, mas ainda não está em nenhum MikroTik`;
  }

  const facts = [];
  if (c.whitelist.length) {
    facts.push(`Na <strong>whitelist</strong> (${c.whitelist.map(relText).join(", ")}): o agente nunca bloqueia este endereço.`);
  }
  if (!c.fail2ban.ok) facts.push(`fail2ban: <span class="st st-bad">erro</span> ${esc(c.fail2ban.error)}`);
  else if (c.fail2ban.matches.length) {
    facts.push("Banido no <strong>fail2ban</strong>: " + c.fail2ban.matches.map((m) =>
      `jail <strong>${esc(m.jail)}</strong> (${relText(m)})${m.replicated ? "" : ' <span class="pill warn">jail não replicada</span>'}`).join("; "));
  } else facts.push("Não está banido no fail2ban.");
  if (!c.blacklist.ok) facts.push(`blacklist: <span class="st st-bad">erro</span> ${esc(c.blacklist.error)}`);
  else if (c.blacklist.matches.length) facts.push("Na <strong>blacklist</strong>: " + c.blacklist.matches.map(relText).join(", "));
  else facts.push("Não está na blacklist.");

  const notBlockedButShould = online.filter((r) => !r.blocked && expected);
  if (notBlockedButShould.length) {
    facts.push(`<span class="st st-bad">atenção</span> deveria estar bloqueado em ${notBlockedButShould.map((r) => esc(r.name)).join(", ")}: o agente ainda não sincronizou ou houve erro (veja o log).`);
  }

  const rows = c.routers.map((r) => {
    let result;
    if (r.status !== "online") result = r.error ? `<span class="muted small">${esc(r.error)}</span>` : "";
    else if (!r.matches.length) result = '<span class="st st-ok">livre</span>';
    else {
      result = r.matches.map((m) => `
        <div>${m.disabled ? '<span class="st st-warn">entrada desativada</span>'
          : (m.relation === "contem" ? '<span class="st st-warn">parte da rede</span>' : '<span class="st st-bad">bloqueado</span>')}
          ${relText(m)} <span class="muted small">${esc(m.comment)}${m.timeout ? ` · expira em ${esc(m.timeout)}` : ""}${m.managed ? "" : " · manual"}</span></div>`).join("");
    }
    return `<tr><td><strong>${esc(r.name)}</strong><div class="muted small mono">${esc(r.host)}</div></td><td>${statusPill(r.status)}</td><td>${result}</td></tr>`;
  }).join("");

  const actions = [];
  if (c.fail2ban.matches.some((m) => m.relation === "igual")) {
    actions.push(`<button type="button" class="btn" data-act="unban" data-ip="${esc(c.query)}">Desbanir no fail2ban</button>`);
  }
  const blExact = c.blacklist.matches.filter((m) => m.relation === "igual");
  c.blacklist.matches.forEach((m) => {
    actions.push(`<button type="button" class="btn" data-act="bl-del" data-entry="${esc(m.entry)}">Tirar ${esc(m.entry)} da blacklist</button>`);
  });
  if (!blExact.length && !c.whitelist.length && c.blacklist.ok) {
    actions.push(`<button type="button" class="btn" data-act="bl-add" data-entry="${esc(c.query)}">Incluir na blacklist</button>`);
  }

  $("#check-result").innerHTML = `
    <div class="verdict ${cls}">
      <div class="verdict-title">${title}</div>
      <ul>${facts.map((f) => `<li>${f}</li>`).join("")}</ul>
      ${actions.length ? `<div class="verdict-actions">${actions.join("")}</div>` : ""}
      <div class="table-wrap"><table class="table"><thead><tr><th>roteador</th><th>status</th><th>resultado</th></tr></thead><tbody>${rows}</tbody></table></div>
    </div>`;
}
$("#check-form").addEventListener("submit", (ev) => { ev.preventDefault(); runCheck(); });

// ---------------------------------------------------------------------------
// roteadores
// ---------------------------------------------------------------------------
function renderRouters() {
  const status = {};
  (overview ? overview.routers : []).forEach((r) => { status[r.id] = r; });
  api("/api/routers").then((d) => {
    routersCache = d.routers;
    $("#count-routers").textContent = d.routers.length;
    $("#routers-table").innerHTML = `<thead><tr><th>nome</th><th>endereço</th><th>usuário</th><th>status</th><th class="center">recebe bloqueios</th><th></th></tr></thead><tbody>` +
      d.routers.map((r) => {
        const st = status[r.id];
        return `<tr>
          <td><strong>${esc(r.name)}</strong> ${r.primary ? '<span class="pill">principal · config.ini</span>' : ""}</td>
          <td class="mono">${esc(r.host)}:${esc(r.port)}${r.use_ssl ? " (SSL)" : ""}</td>
          <td class="mono">${esc(r.username)}</td>
          <td>${st ? statusPill(st.status) : ""}${st && st.error ? `<div class="muted small">${esc(st.error)}</div>` : ""}</td>
          <td class="center">${r.enabled ? '<span class="st st-ok">sim</span>' : '<span class="st st-warn">não</span>'}</td>
          <td><div class="actions">
            <button class="btn small" data-act="test" data-id="${esc(r.id)}">Testar</button>
            ${r.primary ? "" : `<button class="btn small" data-act="edit" data-id="${esc(r.id)}">Editar</button>
            <button class="btn small" data-act="delete" data-id="${esc(r.id)}">Excluir</button>`}
          </div></td></tr>`;
      }).join("") + "</tbody>";
  }).catch((e) => {
    $("#routers-table").innerHTML = `<tbody><tr><td class="empty">${esc(e.message)}</td></tr></tbody>`;
  });
}

$("#routers-table").addEventListener("click", async (ev) => {
  const btn = ev.target.closest("[data-act]");
  if (!btn) return;
  const r = routersCache.find((x) => x.id === btn.dataset.id);
  if (!r) return;
  if (btn.dataset.act === "edit") openRouterDialog(r);
  if (btn.dataset.act === "delete") openDeleteDialog(r);
  if (btn.dataset.act === "test") {
    btn.disabled = true;
    btn.textContent = "Testando…";
    try {
      const t = await api("/api/routers/test", { method: "POST", body: { id: r.id } });
      alert(testSummary(t, r.name));
    } catch (e) {
      alert(`${r.name}: ${e.message}`);
    } finally {
      btn.disabled = false;
      btn.textContent = "Testar";
    }
  }
});

function testSummary(t, name) {
  return t.status === "online"
    ? `${name}: conexão OK\n${t.board} · RouterOS ${t.version} · identity ${t.identity}\n${t.entries} entrada(s) na lista · ${t.latency_ms} ms`
    : `${name}: FALHOU\n${t.error}`;
}

// formulario
const dlg = $("#router-dialog");
const form = $("#router-form");
const F = (n) => form.elements.namedItem(n);
let editing = null;

function openRouterDialog(r) {
  editing = r || null;
  form.reset();
  $("#router-dialog-title").textContent = r ? `Editar ${r.name}` : "Cadastrar MikroTik";
  $("#router-test-result").innerHTML = "";
  F("password").placeholder = r ? "em branco = manter a senha atual" : "";
  F("password").required = !r;
  if (r) {
    ["name", "host", "port", "username", "timeout"].forEach((k) => { F(k).value = r[k]; });
    F("use_ssl").checked = r.use_ssl;
    F("enabled").checked = r.enabled;
  } else {
    F("username").value = "f2b-agent";
    F("enabled").checked = true;
  }
  dlg.showModal();
}

function formData() {
  return {
    id: editing ? editing.id : undefined,
    name: F("name").value.trim(),
    host: F("host").value.trim(),
    port: F("port").value ? Number(F("port").value) : undefined,
    timeout: F("timeout").value ? Number(F("timeout").value) : undefined,
    username: F("username").value.trim(),
    password: F("password").value,
    use_ssl: F("use_ssl").checked,
    enabled: F("enabled").checked,
  };
}

$("#router-add").addEventListener("click", () => openRouterDialog(null));
$("#router-cancel").addEventListener("click", () => dlg.close());
F("use_ssl").addEventListener("change", () => {
  if (!F("port").value || ["8728", "8729"].includes(F("port").value)) F("port").value = F("use_ssl").checked ? 8729 : 8728;
});

$("#router-test").addEventListener("click", async () => {
  const box = $("#router-test-result");
  box.innerHTML = '<p class="muted">Testando conexão…</p>';
  try {
    const t = await api("/api/routers/test", { method: "POST", body: formData() });
    box.innerHTML = t.status === "online"
      ? `<div class="alert ok">Conexão OK: ${esc(t.board)} · RouterOS ${esc(t.version)} · identity ${esc(t.identity)} · ${t.entries} entrada(s) na lista</div>`
      : `<div class="alert">Falhou: ${esc(t.error)}</div>`;
  } catch (e) {
    box.innerHTML = `<div class="alert">${esc(e.message)}</div>`;
  }
});

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const save = $("#router-save");
  save.disabled = true;
  try {
    if (editing) await api(`/api/routers/${editing.id}`, { method: "PUT", body: formData() });
    else await api("/api/routers", { method: "POST", body: formData() });
    dlg.close();
    loadOverview();
  } catch (e) {
    $("#router-test-result").innerHTML = `<div class="alert">${esc(e.message)}</div>`;
  } finally {
    save.disabled = false;
  }
});

// exclusao
const delDlg = $("#delete-dialog");
let deleting = null;
function openDeleteDialog(r) {
  deleting = r;
  $("#delete-name").textContent = r.name;
  $("#delete-error").innerHTML = "";
  $("#delete-flush").checked = true;
  delDlg.showModal();
}
$("#delete-cancel").addEventListener("click", () => delDlg.close());
$("#delete-confirm").addEventListener("click", async () => {
  const btn = $("#delete-confirm");
  btn.disabled = true;
  try {
    const flush = $("#delete-flush").checked ? 1 : 0;
    await api(`/api/routers/${deleting.id}?flush=${flush}`, { method: "DELETE" });
    delDlg.close();
    loadOverview();
  } catch (e) {
    $("#delete-error").innerHTML = `<div class="alert">${esc(e.message)}</div>`;
  } finally {
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// log do agente
// ---------------------------------------------------------------------------
let logLines = [];
async function loadLog() {
  try {
    const d = await api(`/api/log?lines=${$("#log-lines").value}`);
    logLines = d.lines;
    $("#log-file").textContent = d.file + (d.error ? ` — ${d.error}` : "");
    renderLog(true);
  } catch (e) {
    $("#log-box").innerHTML = `<span class="l-error">${esc(e.message)}</span>`;
  }
}
function renderLog(toBottom = false) {
  const f = $("#log-filter").value.trim().toLowerCase();
  const box = $("#log-box");
  const atBottom = toBottom || box.scrollTop + box.clientHeight >= box.scrollHeight - 20;
  box.innerHTML = logLines.filter((l) => !f || l.toLowerCase().includes(f)).map((l) => {
    let cls = "";
    if (l.includes("[ERROR]")) cls = "l-error";
    else if (l.includes("[WARNING]")) cls = "l-warn";
    else if (/BLOQUEADO|BLOQUEARIA/.test(l)) cls = "l-ban";
    else if (/LIBERADO|LIBERARIA|REMOVIDO/.test(l)) cls = "l-unban";
    return `<span class="${cls}">${esc(l)}</span>`;
  }).join("\n") || '<span class="muted">sem linhas</span>';
  if (atBottom) box.scrollTop = box.scrollHeight;
}
$("#log-filter").addEventListener("input", () => renderLog(true));
$("#log-lines").addEventListener("change", loadLog);
$("#log-refresh").addEventListener("click", loadLog);

// ---------------------------------------------------------------------------
// inicio e atualizacao automatica
// ---------------------------------------------------------------------------
let timer = null;
function setAuto(on) {
  clearInterval(timer);
  timer = on ? setInterval(() => {
    loadOverview();
    if ($("#tab-log").classList.contains("active")) loadLog();
  }, 30000) : null;
  try { localStorage.setItem("f2b-auto", on ? "1" : "0"); } catch (_) { /* sem storage */ }
}
$("#auto").addEventListener("change", (ev) => setAuto(ev.target.checked));
$("#refresh").addEventListener("click", loadOverview);

(function init() {
  let tab = "overview";
  let auto = false;
  try {
    tab = localStorage.getItem("f2b-tab") || tab;
    auto = localStorage.getItem("f2b-auto") === "1";
  } catch (_) { /* sem storage */ }
  $("#auto").checked = auto;
  setAuto(auto);
  if ($(`#tab-${tab}`)) showTab(tab);
  loadOverview();
})();

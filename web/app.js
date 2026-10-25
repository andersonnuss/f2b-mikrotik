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
  if (res.status === 401) {  // sessao expirada ou encerrada
    location.replace("/login");
    throw new Error("sessão expirada");
  }
  let data = null;
  try { data = await res.json(); } catch (_) { /* resposta sem JSON */ }
  if (!res.ok) {
    const err = new Error((data && data.error) || `${res.status} ${res.statusText}`);
    err.data = data;
    err.status = res.status;
    throw err;
  }
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

// usuario logado e papeis: a tela esconde o que o papel nao permite (o servidor tambem bloqueia)
let me = null;
const RANK = { leitura: 0, operador: 1, admin: 2 };
const can = (role) => !!me && RANK[me.role] >= RANK[role];
function applyRole() {
  $$("[data-role]").forEach((el) => { el.hidden = !can(el.dataset.role); });
  $("#user-name").textContent = me.name ? `${me.name} (${me.username})` : me.username;
  $("#user-role").textContent = me.role_label;
  $("#user-role").className = `pill ${me.role === "admin" ? "info" : ""}`;
}

// pais: codigo ISO -> bandeira + nome em portugues; sem codigo -> "desconhecido"
let regionNames = null;
try { regionNames = new Intl.DisplayNames(["pt-BR"], { type: "region" }); } catch (_) { /* navegador antigo */ }
function countryName(cc) {
  if (!cc) return "desconhecido";
  try { return (regionNames && regionNames.of(cc)) || cc; } catch (_) { return cc; }
}
function flag(cc) {
  return cc && /^[A-Z]{2}$/.test(cc) ? String.fromCodePoint(...[...cc].map((c) => 0x1f1a5 + c.charCodeAt(0))) : "";
}
function countryLabel(cc) {
  return cc ? `<span title="${esc(cc)}">${flag(cc)} ${esc(countryName(cc))}</span>` : '<span class="muted">desconhecido</span>';
}
const pad = (n) => String(n).padStart(2, "0");
function fmtTs(ts, withDate = true) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  const hm = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  return withDate ? `${pad(d.getDate())}/${pad(d.getMonth() + 1)} ${hm}` : hm;
}
const KIND_LABEL = { ban: "bloqueio (fail2ban)", unban: "desbloqueio (fail2ban)", restore: "restaurado",
  "bl-add": "incluído na blacklist", "bl-del": "removido da blacklist" };
const KIND_CLASS = { ban: "st-bad", "bl-add": "st-bad", unban: "st-ok", "bl-del": "st-ok", restore: "st-muted" };
const kindBadge = (k) => `<span class="st ${KIND_CLASS[k] || ""}">${esc(KIND_LABEL[k] || k)}</span>`;

// ---------------------------------------------------------------------------
// abas
// ---------------------------------------------------------------------------
function showTab(name) {
  $$(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  $$(".tab").forEach((t) => t.classList.toggle("active", t.id === `tab-${name}`));
  if (name === "log") loadLog();
  if (name === "stats") loadStats();
  if (name === "settings") loadSettings();
  if (name === "users") loadUsers();
  if (name === "audit") loadAudit();
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
    if (can("admin")) renderRouters();
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
    ...(o.router_hold ? [[o.holds_count, `retidos no MikroTik (+${o.router_hold} após o fail2ban)`]] : []),
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
      <header><strong>${esc(r.name)}</strong>${statusPill(r.status)}</header>
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
  $("#bl-box").innerHTML = !b.ok ? `<div class="alert">${esc(b.error)}</div>`
    : (b.items.length ? `<div class="bl-list">${b.items.map((it) => `
        <div class="bl-item">
          <button type="button" class="link mono" data-check="${esc(it.entry)}">${esc(it.entry)}</button>
          <span class="muted small bl-comment" title="${esc(it.comment)}">${esc(it.comment)}
            <span class="nowrap">· ${esc(it.created_by || "?")} em ${fmtTs(it.created_at)}</span>
            ${it.expires_at ? `<span class="nowrap">· <strong>expira ${fmtTs(it.expires_at)}</strong></span>` : ""}</span>
          ${it.ignored ? `<span class="pill warn" title="o agente ignora esta entrada">ignorado: ${esc(it.ignored)}</span>` : ""}
          ${can("operador") ? `<button type="button" class="btn small" data-act="bl-del" data-entry="${esc(it.entry)}">Remover</button>` : ""}
        </div>`).join("")}</div>` : '<p class="muted small">vazia</p>');
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
    if (source === "hold" && !e.hold) return false;
    if (onlyDiff && !Object.values(e.routers).some((s) => s === "faltando" || s === "a remover")) return false;
    if (filter && !(e.key.toLowerCase().includes(filter) || e.sources.join(" ").toLowerCase().includes(filter))) return false;
    return true;
  });

  const sort = $("#entries-sort").value;
  if (sort === "blocks") rows.sort((a, b) => b.blocks - a.blocks || (b.last_block || 0) - (a.last_block || 0));
  if (sort === "recent") rows.sort((a, b) => (b.last_block || 0) - (a.last_block || 0));
  if (sort === "country") rows.sort((a, b) => countryName(a.country).localeCompare(countryName(b.country), "pt-BR") || b.blocks - a.blocks);

  $("#count-entries").textContent = overview.entries.length;
  $("#entries-info").textContent = `${rows.length} de ${overview.entries.length}`;
  const head = `<thead><tr><th>IP / rede</th><th>país</th><th class="num" title="quantas vezes foi bloqueado (histórico)">bloqueios</th><th>fail2ban</th><th>blacklist</th>
    ${routers.map((r) => `<th class="center">${esc(r.name)}</th>`).join("")}<th></th></tr></thead>`;
  const body = rows.length ? rows.slice(0, 3000).map((e) => `<tr>
      <td><button type="button" class="link mono" data-check="${esc(e.key)}">${esc(e.key)}</button>
        ${e.note ? `<div class="muted small">${esc(e.note)}</div>` : ""}
        ${!e.sources.length ? '<div class="muted small">só no roteador</div>' : ""}</td>
      <td class="nowrap">${countryLabel(e.country)}</td>
      <td class="num" title="${e.last_block ? `último bloqueio: ${fmtTs(e.last_block)}` : "sem registro no histórico"}">${e.blocks || '<span class="muted">0</span>'}</td>
      <td>${e.jails.map((j) => `<span class="pill">${esc(j)}</span>`).join(" ")}
        ${e.hold ? `<span class="pill warn" title="o fail2ban já liberou; o MikroTik mantém o bloqueio (reincidência ${e.hold.cycles}, jail ${esc(e.hold.jails)})">retido até ${fmtTs(e.hold.release_at)}</span>` : ""}</td>
      <td>${e.blacklist ? '<span class="pill info">sim</span>' : ""}</td>
      ${routers.map((r) => `<td class="center">${stateBadge(e.routers[r.id])}</td>`).join("")}
      <td><div class="actions">${rowActions(e)}</div></td>
    </tr>`).join("")
    : `<tr><td colspan="${routers.length + 6}" class="empty">nada encontrado</td></tr>`;
  $("#entries-table").innerHTML = head + `<tbody>${body}</tbody>`;
}

function rowActions(e) {
  if (!can("operador")) return "";
  const out = [];
  if (e.jails.length) out.push(`<button type="button" class="btn small" data-act="unban" data-ip="${esc(e.key)}">Desbanir</button>`);
  else if (e.hold) out.push(`<button type="button" class="btn small" data-act="release" data-ip="${esc(e.key)}">Liberar no MikroTik</button>`);
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
    + "O agente libera o IP nos MikroTiks em cerca de 2 segundos (desbanir pelo painel não aplica a retenção).";
  if (e && e.blacklist) msg += `\n\nAtenção: ${ip} também está na blacklist e continuará bloqueado nos roteadores.`;
  if (!confirm(msg)) return;
  const r = await api("/api/unban", { method: "POST", body: { ip } });
  toast(r.in_blacklist
    ? `${r.ip} desbanido de ${r.jails.join(", ")}, mas continua bloqueado pela blacklist.`
    : `${r.ip} desbanido de ${r.jails.join(", ")}. O agente está liberando nos MikroTiks…`, r.in_blacklist ? "warn" : "ok");
  refreshSoon();
}

async function doRelease(ip) {
  const e = overview && overview.entries.find((x) => x.key === ip);
  const until = e && e.hold ? ` (retido até ${fmtTs(e.hold.release_at)})` : "";
  if (!confirm(`Liberar ${ip} nos MikroTiks agora${until}?

O fail2ban já tinha liberado este IP; o agente o remove dos roteadores em cerca de 2 segundos.`)) return;
  const r = await api("/api/release", { method: "POST", body: { ip } });
  if (r.in_blacklist) toast(`Retenção de ${r.ip} liberada, mas ele continua bloqueado pela blacklist.`, "warn");
  else if (r.still_banned.length) toast(`Retenção de ${r.ip} liberada, mas ele voltou a ser banido no fail2ban (${r.still_banned.join(", ")}).`, "warn");
  else toast(`${r.ip} liberado. O agente está removendo dos MikroTiks…`);
  refreshSoon();
}

async function doBlacklistAdd(entry, comment, expires = 0) {
  if (comment === undefined) {
    comment = prompt(`Incluir ${entry} na blacklist (permanente)?\nEle será bloqueado em todos os MikroTiks.\n\nMotivo (opcional):`, "");
    if (comment === null) return;
  }
  const r = await api("/api/blacklist", { method: "POST", body: { entry, comment, expires } });
  toast(`${r.entry} incluído na blacklist${expires ? " (com validade)" : ""}. O agente está bloqueando nos MikroTiks…`);
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
  if (!btn || !["unban", "release", "bl-add", "bl-del"].includes(btn.dataset.act)) return;
  btn.disabled = true;
  try {
    if (btn.dataset.act === "unban") await doUnban(btn.dataset.ip);
    if (btn.dataset.act === "release") await doRelease(btn.dataset.ip);
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
    await doBlacklistAdd(fe.namedItem("entry").value.trim(), fe.namedItem("comment").value.trim(),
      Number(fe.namedItem("expires").value));
    ev.target.reset();
  } catch (e) {
    toast(e.message, "bad");
  }
});
["#entries-filter", "#entries-source", "#entries-diff", "#entries-sort"].forEach((s) => $(s).addEventListener("input", renderEntries));

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
  const ci = c.country_info;
  const geoSource = { ipinfo: "ipinfo", rir: "registro RIR" }[ci.source];
  facts.push(`País: ${c.is_network ? "da rede: " : ""}${countryLabel(ci.cc)}`
    + (geoSource ? ` <span class="muted small">(${geoSource})</span>` : "")
    + (ci.asn || ci.as_name ? ` · provedor: ${esc([ci.asn, ci.as_name].filter(Boolean).join(" "))}` : ""));
  if (c.hold) {
    facts.push(`<strong>Retido no MikroTik</strong> até ${fmtTs(c.hold.release_at)}: o fail2ban liberou em ${fmtTs(c.hold.last_unban)}`
      + ` (jail ${esc(c.hold.jails)}${c.hold.cycles > 1 ? `, ${c.hold.cycles}ª reincidência` : ""}).`);
  }
  const h = c.history;
  if (!c.meta.events) facts.push('<span class="muted">Histórico desativado no config.ini ([agent] events_db).</span>');
  else if (h.blocks || h.unblocks) {
    facts.push(`Histórico: <strong>bloqueado ${h.blocks} ${h.blocks === 1 ? "vez" : "vezes"}</strong>`
      + (h.blocks ? ` (primeira em ${fmtTs(h.first)}, última em ${fmtTs(h.last)})` : "")
      + ` · ${h.unblocks} desbloqueio(s)`
      + `<details class="history"><summary class="muted small">últimos eventos</summary><ul>${h.recent.map((ev) =>
        `<li>${fmtTs(ev.ts)} ${kindBadge(ev.kind)} <span class="muted small">${esc(ev.jail)}${c.is_network ? ` · ${esc(ev.ip)}` : ""}</span></li>`).join("")}</ul></details>`);
  } else facts.push("Histórico: nunca foi bloqueado.");
  if (c.whitelist.length) {
    facts.push(`Na <strong>whitelist</strong> (${c.whitelist.map(relText).join(", ")}): o agente nunca bloqueia este endereço.`);
  }
  if (!c.fail2ban.ok) facts.push(`fail2ban: <span class="st st-bad">erro</span> ${esc(c.fail2ban.error)}`);
  else if (c.fail2ban.matches.length) {
    facts.push("Banido no <strong>fail2ban</strong>: " + c.fail2ban.matches.map((m) =>
      `jail <strong>${esc(m.jail)}</strong> (${relText(m)})${m.replicated ? "" : ' <span class="pill warn">jail não replicada</span>'}`).join("; "));
  } else facts.push("Não está banido no fail2ban.");
  if (!c.blacklist.ok) facts.push(`blacklist: <span class="st st-bad">erro</span> ${esc(c.blacklist.error)}`);
  else if (c.blacklist.matches.length) {
    facts.push("Na <strong>blacklist</strong>: " + c.blacklist.matches.map((m) => relText(m)
      + (m.expires_at ? ` <span class="muted small">(expira ${fmtTs(m.expires_at)})</span>` : "")).join(", "));
  }
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
  if (can("operador") && c.hold && !c.fail2ban.matches.some((m) => m.relation === "igual")) {
    actions.push(`<button type="button" class="btn" data-act="release" data-ip="${esc(c.query)}">Liberar no MikroTik</button>`);
  }
  if (!can("operador")) { /* leitura: sem acoes */ } else if (c.fail2ban.matches.some((m) => m.relation === "igual")) {
    actions.push(`<button type="button" class="btn" data-act="unban" data-ip="${esc(c.query)}">Desbanir no fail2ban</button>`);
  }
  const blExact = c.blacklist.matches.filter((m) => m.relation === "igual");
  if (can("operador")) {
    c.blacklist.matches.forEach((m) => {
      actions.push(`<button type="button" class="btn" data-act="bl-del" data-entry="${esc(m.entry)}">Tirar ${esc(m.entry)} da blacklist</button>`);
    });
  }
  if (can("operador") && !blExact.length && !c.whitelist.length && c.blacklist.ok) {
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
    $("#routers-table").innerHTML = `<thead><tr><th>nome</th><th>endereço</th><th>usuário</th><th>status</th><th class="center">recebe bloqueios</th><th>última alteração</th><th></th></tr></thead><tbody>` +
      (d.routers.length ? d.routers.map((r) => {
        const st = status[r.id];
        return `<tr>
          <td><strong>${esc(r.name)}</strong></td>
          <td class="mono">${esc(r.host)}:${esc(r.port)}${r.use_ssl ? " (SSL)" : ""}</td>
          <td class="mono">${esc(r.username)}</td>
          <td>${st ? statusPill(st.status) : ""}${st && st.error ? `<div class="muted small">${esc(st.error)}</div>` : ""}</td>
          <td class="center">${r.enabled ? '<span class="st st-ok">sim</span>' : '<span class="st st-warn">não</span>'}</td>
          <td class="small muted nowrap">${esc(r.updated_by || "")} ${fmtTs(r.updated_at)}</td>
          <td><div class="actions">
            <button class="btn small" data-act="test" data-id="${esc(r.id)}">Testar</button>
            <button class="btn small" data-act="edit" data-id="${esc(r.id)}">Editar</button>
            <button class="btn small" data-act="delete" data-id="${esc(r.id)}">Excluir</button>
          </div></td></tr>`;
      }).join("") : '<tr><td colspan="7" class="empty">nenhum roteador cadastrado: o agente não tem para onde replicar os bloqueios</td></tr>')
      + "</tbody>";
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
// estatisticas
// ---------------------------------------------------------------------------
let statsHours = 24;
let statsData = null;

async function loadStats() {
  try {
    statsData = await api(`/api/stats?hours=${statsHours}`);
    $("#stats-error").innerHTML = "";
    renderStats();
  } catch (e) {
    $("#stats-error").innerHTML = `<div class="alert">Falha ao carregar: ${esc(e.message)}</div>`;
  }
}

$$(".segmented button").forEach((b) => b.addEventListener("click", () => {
  statsHours = Number(b.dataset.hours);
  $$(".segmented button").forEach((x) => x.classList.toggle("active", x === b));
  loadStats();
}));

function renderStats() {
  const s = statsData;
  const t = s.totals;
  const m = s.meta;
  const period = s.hours === 24 ? "24 h" : `${s.hours / 24} dias`;
  $("#stats-meta").innerHTML = [
    m.events ? (m.events_since ? `histórico desde ${fmtTs(m.events_since)}` : "histórico vazio") : "histórico desativado",
    m.ipinfo ? `países: ipinfo (${m.ipinfo.cached} IP(s) em cache${m.ipinfo.queued ? `, ${m.ipinfo.queued} na fila` : ""})`
      + (m.ipinfo.error ? ` <span class="st st-warn">${esc(m.ipinfo.error)}</span>` : "") : "",
    !m.geo ? (m.ipinfo ? "" : "países desativados")
      : m.geo_ready ? `${m.ipinfo ? "reserva: " : "países: "}tabela dos RIRs de ${esc(m.geo_updated)}`
        : (m.geo_error ? `tabela dos RIRs indisponível (${esc(m.geo_error)})` : "baixando tabela dos RIRs…"),
  ].filter(Boolean).join(" · ");
  $("#stats-kpis").innerHTML = [
    [t.blocks_1h, "bloqueios na última hora"],
    [t.unblocks_1h, "desbloqueios na última hora"],
    [t.blocks, `bloqueios em ${period}`],
    [t.unblocks, `desbloqueios em ${period}`],
    [t.avg_per_hour.toLocaleString("pt-BR"), "bloqueios por hora (média)"],
    [s.unique_ips, `IPs distintos bloqueados em ${period}`],
  ].map(([v, l]) => `<div class="stat"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");
  $("#chart-title").textContent = `Bloqueios e desbloqueios por hora · ${period}`
    + (t.peak_ts ? ` · pico de ${t.peak_blocks} às ${fmtTs(t.peak_ts)}` : "");

  drawHourly(s.series);
  $("#hourly-table").innerHTML = "<thead><tr><th>hora</th><th class=\"num\">bloqueios</th><th class=\"num\">desbloqueios</th></tr></thead><tbody>"
    + s.series.slice().reverse().map((p) => `<tr><td>${fmtTs(p.ts)}</td><td class="num">${p.blocks}</td><td class="num">${p.unblocks}</td></tr>`).join("")
    + "</tbody>";

  $("#top-ips-period").textContent = `(${period})`;
  $("#top-ips").innerHTML = s.top_ips.length
    ? `<thead><tr><th>IP</th><th>país</th><th class="num">no período</th><th class="num">total</th><th>jail</th><th>último</th></tr></thead><tbody>`
      + s.top_ips.map((r) => `<tr>
          <td><button type="button" class="link mono" data-check="${esc(r.ip)}">${esc(r.ip)}</button></td>
          <td class="nowrap">${countryLabel(r.country)}</td>
          <td class="num">${r.blocks}</td><td class="num">${r.total}</td>
          <td>${r.jails.map((j) => `<span class="pill">${esc(j)}</span>`).join(" ")}</td>
          <td class="nowrap">${fmtTs(r.last)}</td></tr>`).join("") + "</tbody>"
    : '<tbody><tr><td class="empty">nenhum bloqueio no período</td></tr></tbody>';

  hbars("#top-countries", s.top_countries.map((c) => ({ label: countryLabel(c.country), value: c.blocks, extra: `${c.ips} IP(s)` })));
  hbars("#top-jails", s.top_jails.map((j) => ({ label: esc(j.jail), value: j.blocks })));

  $("#recent-events").innerHTML = s.recent.length
    ? "<thead><tr><th>quando</th><th>evento</th><th>IP</th><th>país</th><th>jail / origem</th></tr></thead><tbody>"
      + s.recent.map((ev) => `<tr><td class="nowrap">${fmtTs(ev.ts)}</td><td>${kindBadge(ev.kind)}</td>
          <td><button type="button" class="link mono" data-check="${esc(ev.ip)}">${esc(ev.ip)}</button></td>
          <td class="nowrap">${countryLabel(ev.country)}</td><td>${esc(ev.jail)}</td></tr>`).join("") + "</tbody>"
    : '<tbody><tr><td class="empty">nenhum evento registrado ainda</td></tr></tbody>';
}

// barras horizontais de uma serie so (o titulo nomeia a serie; sem legenda)
function hbars(sel, items) {
  const max = Math.max(1, ...items.map((i) => i.value));
  $(sel).innerHTML = items.length ? items.map((i) => `
    <div class="hbar-row">
      <div class="hbar-label">${i.label}</div>
      <div class="hbar-track"><div class="hbar-fill" data-w="${(i.value / max) * 100}"></div></div>
      <div class="hbar-value">${i.value}${i.extra ? ` <span class="muted small">· ${esc(i.extra)}</span>` : ""}</div>
    </div>`).join("") : '<p class="muted small">nenhum bloqueio no período</p>';
  // largura via CSSOM: a CSP do painel nao permite style="" inline
  $$(`${sel} .hbar-fill`).forEach((el) => { el.style.width = `${el.dataset.w}%`; });
}

// barras agrupadas por hora: azul = bloqueios, laranja = desbloqueios, um eixo so
function drawHourly(series) {
  const box = $("#hourly-chart");
  const W = Math.max(320, box.clientWidth || 900);
  const H = 240;
  const M = { top: 12, right: 8, bottom: 26, left: 36 };
  const iw = W - M.left - M.right;
  const ih = H - M.top - M.bottom;
  const n = series.length;
  const maxV = Math.max(1, ...series.map((p) => Math.max(p.blocks, p.unblocks)));
  const step = niceStep(maxV);
  const top = Math.ceil(maxV / step) * step;
  const y = (v) => M.top + ih - (v / top) * ih;
  const slot = iw / n;
  const gap = 2;
  const bw = Math.max(1, Math.min(14, (slot - gap * 2) / 2));

  const bar = (x, v, cls) => {
    if (!v) return "";
    const h = ih * (v / top);
    const r = Math.min(4, bw / 2, h);
    const y0 = M.top + ih;
    return `<path class="${cls}" d="M${x},${y0} V${y0 - h + r} Q${x},${y0 - h} ${x + r},${y0 - h} H${x + bw - r} Q${x + bw},${y0 - h} ${x + bw},${y0 - h + r} V${y0} Z"/>`;
  };

  let grid = "";
  for (let v = 0; v <= top; v += step) {
    grid += `<line class="grid" x1="${M.left}" x2="${W - M.right}" y1="${y(v)}" y2="${y(v)}"/>`
      + `<text class="axis" x="${M.left - 6}" y="${y(v) + 4}" text-anchor="end">${v}</text>`;
  }
  const every = n <= 24 ? 3 : 24;
  // ate 48 h: barras agrupadas; acima disso as barras ficariam com 1 px, entao vira linha
  const asLines = n > 48;
  let labels = "";
  let bars = "";
  if (asLines) {
    const pts = (key) => series.map((p, i) => `${(M.left + slot * i + slot / 2).toFixed(1)},${y(p[key]).toFixed(1)}`).join(" ");
    bars = `<polyline class="l2" points="${pts("unblocks")}"/><polyline class="l1" points="${pts("blocks")}"/>`;
  }
  series.forEach((p, i) => {
    const cx = M.left + slot * i + slot / 2;
    if (!asLines) bars += bar(cx - bw - gap / 2, p.blocks, "b1") + bar(cx + gap / 2, p.unblocks, "b2");
    const d = new Date(p.ts * 1000);
    if (d.getHours() % every === 0) {
      const txt = n <= 24 ? `${pad(d.getHours())}h` : `${pad(d.getDate())}/${pad(d.getMonth() + 1)}`;
      labels += `<text class="axis" x="${cx}" y="${H - 8}" text-anchor="middle">${txt}</text>`;
    }
  });

  box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img"
      aria-label="Bloqueios e desbloqueios por hora">${grid}<g>${bars}</g>${labels}
      <line class="hover-line" x1="0" x2="0" y1="${M.top}" y2="${M.top + ih}" visibility="hidden"/></svg>
    <div class="chart-tip" hidden></div>`;

  const svg = box.querySelector("svg");
  const tip = box.querySelector(".chart-tip");
  const line = box.querySelector(".hover-line");
  svg.addEventListener("mousemove", (ev) => {
    const rect = svg.getBoundingClientRect();
    const x = (ev.clientX - rect.left) * (W / rect.width);
    const i = Math.floor((x - M.left) / slot);
    if (i < 0 || i >= n) { tip.hidden = true; line.setAttribute("visibility", "hidden"); return; }
    const p = series[i];
    const cx = M.left + slot * i + slot / 2;
    line.setAttribute("x1", cx); line.setAttribute("x2", cx); line.setAttribute("visibility", "visible");
    const end = new Date((p.ts + 3600) * 1000);
    tip.innerHTML = `<div class="tip-title">${fmtTs(p.ts)}–${pad(end.getHours())}:00</div>
      <div><span class="swatch s1"></span>bloqueios <strong>${p.blocks}</strong></div>
      <div><span class="swatch s2"></span>desbloqueios <strong>${p.unblocks}</strong></div>`;
    tip.hidden = false;
    const px = (cx / W) * rect.width;
    tip.style.left = `${Math.min(Math.max(px + 12, 0), rect.width - 170)}px`;
    tip.style.top = "8px";
  });
  svg.addEventListener("mouseleave", () => { tip.hidden = true; line.setAttribute("visibility", "hidden"); });
}

function niceStep(max) {
  const raw = max / 4;
  const pow = 10 ** Math.floor(Math.log10(raw));
  const f = raw / pow;
  return Math.max(1, (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * pow);
}

window.addEventListener("resize", () => {
  if (statsData && $("#tab-stats").classList.contains("active")) drawHourly(statsData.series);
});

// ---------------------------------------------------------------------------
// configuracoes e whitelist (admin)
// ---------------------------------------------------------------------------
const sform = $("#settings-form");
let settingsData = null;

async function loadSettings() {
  try {
    settingsData = await api("/api/settings");
    $("#settings-error").innerHTML = "";
    renderSettings();
  } catch (e) {
    $("#settings-error").innerHTML = `<div class="alert">${esc(e.message)}</div>`;
  }
}

function renderSettings() {
  const v = settingsData.values;
  Object.entries(v).forEach(([k, val]) => {
    const el = sform.elements.namedItem(k);
    if (!el) return;
    if (el.type === "checkbox") el.checked = !!val;
    else if (k === "ipinfo_token") { el.value = ""; el.placeholder = val ? "token configurado (em branco = manter)" : "sem token"; }
    else el.value = val;
  });
  $("#settings-info").textContent = "";
  const ro = settingsData.readonly;
  $("#settings-readonly").innerHTML = [
    ["address-list no MikroTik", ro.address_list], ["prefixo dos comentários", ro.comment_prefix],
    ["log do fail2ban", ro.fail2ban_log], ["banco de configuração", ro.config_db], ["histórico de eventos", ro.events_db],
  ].map(([k, val]) => `<dt>${esc(k)}</dt><dd class="mono small">${esc(val || "—")}</dd>`).join("");
  $("#wl-admin").innerHTML = settingsData.whitelist.length ? `<div class="bl-list">${settingsData.whitelist.map((w) => `
    <div class="bl-item">
      <span class="mono">${esc(w.entry)}</span>
      <span class="muted small bl-comment" title="${esc(w.comment)}">${esc(w.comment)}
        <span class="nowrap">· ${esc(w.created_by || "?")} em ${fmtTs(w.created_at)}</span></span>
      <button type="button" class="btn small" data-wl-del="${esc(w.entry)}">Remover</button>
    </div>`).join("")}</div>` : '<p class="muted small">vazia: o agente pode bloquear qualquer IP</p>';
}

sform.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const values = {};
  Object.keys(settingsData.values).forEach((k) => {
    const el = sform.elements.namedItem(k);
    if (!el) return;
    if (el.type === "checkbox") values[k] = el.checked;
    else if (k === "ipinfo_token") { if (el.value) values[k] = el.value; }
    else values[k] = el.value;
  });
  try {
    const r = await api("/api/settings", { method: "PUT", body: { values } });
    toast(r.changed.length ? `Configurações salvas: ${r.changed.join(", ")}. O agente aplica em ~2 s.`
      + (r.holds_released.length ? ` Retenção desligada: ${r.holds_released.length} IP(s) liberado(s) nos MikroTiks.` : "")
      : "Nada mudou.");
    loadSettings();
  } catch (e) {
    toast(e.message, "bad");
  }
});

$("#wl-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const fe = ev.target.elements;
  try {
    const r = await api("/api/whitelist", { method: "POST",
      body: { entry: fe.namedItem("entry").value.trim(), comment: fe.namedItem("comment").value.trim() } });
    ev.target.reset();
    toast(r.blacklist_ignored.length
      ? `${r.entry} incluído na whitelist. Deixam de ser bloqueados: ${r.blacklist_ignored.join(", ")}.`
      : `${r.entry} incluído na whitelist. O agente o libera nos MikroTiks se estiver bloqueado.`,
    r.blacklist_ignored.length ? "warn" : "ok");
    loadSettings();
    refreshSoon();
  } catch (e) {
    toast(e.message, "bad");
  }
});

$("#wl-admin").addEventListener("click", async (ev) => {
  const btn = ev.target.closest("[data-wl-del]");
  if (!btn) return;
  const entry = btn.dataset.wlDel;
  if (!confirm(`Remover ${entry} da whitelist?\n\nSe o fail2ban banir um IP dessa faixa, ele passa a ser bloqueado nos MikroTiks.`)) return;
  try {
    await api("/api/whitelist", { method: "DELETE", body: { entry } });
  } catch (e) {
    if (!(e.data && e.data.needs_confirm) || !confirm(`${e.message}`)) {
      if (!(e.data && e.data.needs_confirm)) toast(e.message, "bad");
      return;
    }
    try {
      await api("/api/whitelist", { method: "DELETE", body: { entry, confirm: true } });
    } catch (e2) {
      toast(e2.message, "bad");
      return;
    }
  }
  toast(`${entry} removido da whitelist.`);
  loadSettings();
  refreshSoon();
});

// ---------------------------------------------------------------------------
// usuarios (admin)
// ---------------------------------------------------------------------------
const udlg = $("#user-dialog");
const uform = $("#user-form");
const U = (n) => uform.elements.namedItem(n);
let usersCache = [];
let editingUser = null;

async function loadUsers() {
  try {
    const d = await api("/api/users");
    usersCache = d.users;
    $("#users-table").innerHTML = `<thead><tr><th>usuário</th><th>nome</th><th>papel</th><th>situação</th><th>último acesso</th><th>criado</th><th></th></tr></thead><tbody>`
      + d.users.map((u) => `<tr>
        <td class="mono">${esc(u.username)}${u.username.toLowerCase() === me.username.toLowerCase() ? ' <span class="pill">você</span>' : ""}</td>
        <td>${esc(u.name)}</td>
        <td><span class="pill ${u.role === "admin" ? "info" : ""}">${esc(d.roles[u.role] || u.role)}</span></td>
        <td>${u.enabled ? '<span class="st st-ok">ativo</span>' : '<span class="st st-warn">desativado</span>'}</td>
        <td class="nowrap small">${fmtTs(u.last_login)}</td>
        <td class="nowrap small muted">${esc(u.created_by || "")} ${fmtTs(u.created_at)}</td>
        <td><div class="actions">
          <button class="btn small" data-user-edit="${esc(u.username)}">Editar</button>
          ${u.username.toLowerCase() === me.username.toLowerCase() ? "" : `<button class="btn small" data-user-del="${esc(u.username)}">Excluir</button>`}
        </div></td></tr>`).join("") + "</tbody>";
  } catch (e) {
    $("#users-table").innerHTML = `<tbody><tr><td class="empty">${esc(e.message)}</td></tr></tbody>`;
  }
}

function openUserDialog(u) {
  editingUser = u || null;
  uform.reset();
  $("#user-error").innerHTML = "";
  $("#user-dialog-title").textContent = u ? `Editar ${u.username}` : "Cadastrar usuário";
  U("username").readOnly = !!u;
  U("password").required = !u;
  U("password").placeholder = u ? "em branco = manter a senha" : "mínimo 8 caracteres";
  if (u) {
    U("username").value = u.username;
    U("name").value = u.name;
    U("role").value = u.role;
    U("enabled").checked = !!u.enabled;
  }
  udlg.showModal();
}

$("#user-add").addEventListener("click", () => openUserDialog(null));
$("#user-cancel").addEventListener("click", () => udlg.close());
$("#users-table").addEventListener("click", async (ev) => {
  const ed = ev.target.closest("[data-user-edit]");
  const del = ev.target.closest("[data-user-del]");
  if (ed) openUserDialog(usersCache.find((u) => u.username === ed.dataset.userEdit));
  if (del) {
    const name = del.dataset.userDel;
    if (!confirm(`Excluir o usuário ${name}?\n\nAs sessões abertas dele são encerradas. O histórico de auditoria é mantido.`)) return;
    try {
      await api(`/api/users/${encodeURIComponent(name)}`, { method: "DELETE" });
      toast(`Usuário ${name} excluído.`);
      loadUsers();
    } catch (e) {
      toast(e.message, "bad");
    }
  }
});

uform.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const body = { name: U("name").value.trim(), role: U("role").value, enabled: U("enabled").checked };
  if (U("password").value) body.password = U("password").value;
  try {
    if (editingUser) {
      await api(`/api/users/${encodeURIComponent(editingUser.username)}`, { method: "PUT", body });
    } else {
      await api("/api/users", { method: "POST", body: Object.assign(body, { username: U("username").value.trim() }) });
    }
    udlg.close();
    toast(editingUser ? `Usuário ${editingUser.username} atualizado.` : "Usuário cadastrado.");
    loadUsers();
  } catch (e) {
    $("#user-error").innerHTML = `<div class="alert">${esc(e.message)}</div>`;
  }
});

// ---------------------------------------------------------------------------
// auditoria (admin)
// ---------------------------------------------------------------------------
const aform = $("#audit-form");
let auditRows = [];

function auditQuery() {
  const fe = aform.elements;
  const params = new URLSearchParams();
  ["actor", "action", "text"].forEach((k) => { if (fe.namedItem(k).value.trim()) params.set(k, fe.namedItem(k).value.trim()); });
  const day = (v, plus) => (v ? String(Math.floor(new Date(`${v}T00:00:00`).getTime() / 1000) + plus) : "");
  if (fe.namedItem("since").value) params.set("since", day(fe.namedItem("since").value, 0));
  if (fe.namedItem("until").value) params.set("until", day(fe.namedItem("until").value, 86400));
  return params;
}

async function loadAudit(more = false) {
  const params = auditQuery();
  if (more && auditRows.length) params.set("before", auditRows[auditRows.length - 1].id);
  try {
    const d = await api(`/api/audit?${params}`);
    auditRows = more ? auditRows.concat(d.rows) : d.rows;
    const sel = aform.elements.namedItem("actor");
    const current = sel.value;
    sel.innerHTML = '<option value="">todos os usuários</option>'
      + d.actors.map((a) => `<option value="${esc(a)}">${esc(a)}</option>`).join("");
    sel.value = current;
    renderAudit();
    $("#audit-more").hidden = !d.more;
  } catch (e) {
    $("#audit-table").innerHTML = `<tbody><tr><td class="empty">${esc(e.message)}</td></tr></tbody>`;
  }
}

function auditDetails(d) {
  if (!d) return "";
  if (typeof d !== "object") return esc(d);
  return Object.entries(d).map(([k, v]) => {
    const val = Array.isArray(v) && v.length === 2 ? `${JSON.stringify(v[0])} → ${JSON.stringify(v[1])}`
      : (typeof v === "object" ? JSON.stringify(v) : String(v));
    return `<span class="nowrap"><span class="muted">${esc(k)}:</span> ${esc(val)}</span>`;
  }).join(" · ");
}

function renderAudit() {
  $("#audit-table").innerHTML = "<thead><tr><th>quando</th><th>usuário</th><th>IP</th><th>ação</th><th>alvo</th><th>detalhes</th></tr></thead><tbody>"
    + (auditRows.length ? auditRows.map((r) => `<tr>
      <td class="nowrap small">${fmtTs(r.ts)}:${pad(new Date(r.ts * 1000).getSeconds())}</td>
      <td class="mono small">${esc(r.actor)}</td>
      <td class="mono small">${esc(r.ip)}</td>
      <td><span class="st ${/falha|negado|bloqueado|erro/.test(r.action) ? "st-bad" : "st-muted"}">${esc(r.action)}</span></td>
      <td class="mono small">${esc(r.target)}</td>
      <td class="small">${auditDetails(r.details)}</td></tr>`).join("")
      : '<tr><td colspan="6" class="empty">nenhum registro com esses filtros</td></tr>')
    + "</tbody>";
}

aform.addEventListener("submit", (ev) => { ev.preventDefault(); loadAudit(); });
$("#audit-more").addEventListener("click", () => loadAudit(true));
$("#audit-csv").addEventListener("click", () => {
  window.location.href = new URL(`/api/audit.csv?${auditQuery()}`, location.origin).href;
});

// ---------------------------------------------------------------------------
// minha senha e sair
// ---------------------------------------------------------------------------
const pdlg = $("#password-dialog");
const pform = $("#password-form");
$("#change-pass").addEventListener("click", () => { pform.reset(); $("#password-error").innerHTML = ""; pdlg.showModal(); });
$("#password-cancel").addEventListener("click", () => pdlg.close());
pform.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const fe = pform.elements;
  if (fe.namedItem("new").value !== fe.namedItem("again").value) {
    $("#password-error").innerHTML = '<div class="alert">as senhas novas não conferem</div>';
    return;
  }
  try {
    await api("/api/me/password", { method: "POST",
      body: { current: fe.namedItem("current").value, new: fe.namedItem("new").value } });
    pdlg.close();
    toast("Senha alterada. Suas outras sessões abertas foram encerradas.");
  } catch (e) {
    $("#password-error").innerHTML = `<div class="alert">${esc(e.message)}</div>`;
  }
});
$("#logout").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); } catch (_) { /* ja saiu */ }
  location.replace("/login");
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
    if ($("#tab-stats").classList.contains("active")) loadStats();
  }, 30000) : null;
  try { localStorage.setItem("f2b-auto", on ? "1" : "0"); } catch (_) { /* sem storage */ }
}
$("#auto").addEventListener("change", (ev) => setAuto(ev.target.checked));
$("#refresh").addEventListener("click", loadOverview);

(async function init() {
  try {
    me = await api("/api/me");
  } catch (_) {
    return;  // sem sessao: api() ja levou para /login
  }
  applyRole();
  let tab = "overview";
  let auto = false;
  try {
    tab = localStorage.getItem("f2b-tab") || tab;
    auto = localStorage.getItem("f2b-auto") === "1";
  } catch (_) { /* sem storage */ }
  const btn = $(`.tabs [data-tab="${tab}"]`);
  if (!btn || btn.hidden) tab = "overview";
  $("#auto").checked = auto;
  setAuto(auto);
  showTab(tab);
  loadOverview();
})();

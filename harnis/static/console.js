// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmad Karawash
//
// Harnis web console. Plain JavaScript, no dependencies, served under a strict
// Content-Security-Policy (no inline scripts or styles, no third-party hosts).
// Every value from the API is inserted with textContent, never as HTML.
"use strict";

(() => {
  // ---------------------------------------------------------------------------
  // Small helpers
  // ---------------------------------------------------------------------------
  const store = {  // sessionStorage: cleared when the tab closes; may be unavailable
    get(k) { try { return sessionStorage.getItem("harnis." + k); } catch { return null; } },
    set(k, v) { try { sessionStorage.setItem("harnis." + k, v); } catch { /* private mode */ } },
    del(k) { try { sessionStorage.removeItem("harnis." + k); } catch { /* ignore */ } },
  };

  function h(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else if (v === true) e.setAttribute(k, "");
      else e.setAttribute(k, v);
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      e.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return e;
  }
  const $ = (sel, root = document) => root.querySelector(sel);

  function toast(text, kind) {
    const t = h("div", { class: "toast" + (kind ? " " + kind : ""), text });
    $("#toasts").append(t);
    setTimeout(() => t.remove(), kind === "error" ? 7000 : 4000);
  }

  function fmtTime(v) {
    if (!v) return "";
    const d = new Date(typeof v === "number" ? v * 1000 : v);
    return isNaN(d) ? String(v) : d.toLocaleString();
  }
  function ago(v) {
    const d = new Date(v);
    if (isNaN(d)) return "";
    const s = Math.round((Date.now() - d.getTime()) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return Math.floor(s / 60) + " min ago";
    if (s < 86400) return Math.floor(s / 3600) + " h ago";
    return d.toLocaleDateString();
  }
  const money = (v) => "$" + Number(v || 0).toFixed(4);
  const num = (v) => Number(v || 0).toLocaleString();

  function jwtClaims(token) {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    try {
      const json = atob(parts[1].replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(parts[1].length / 4) * 4, "="));
      return JSON.parse(decodeURIComponent(Array.from(json, (c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join("")));
    } catch { return null; }
  }

  const STATUS_KIND = {
    completed: "ok", approved: "ok", awaiting_approval: "warn", pending: "warn", running: "accent",
    idle: "", rejected: "danger", denied: "danger", failed: "danger", escalated: "danger", expired: "",
  };
  const statusPill = (s) => h("span", { class: "pill " + (STATUS_KIND[s] || ""), text: String(s || "").replace(/_/g, " ") });

  // ---------------------------------------------------------------------------
  // State and API access
  // ---------------------------------------------------------------------------
  const state = { config: null, token: null, me: null, ws: null, live: false, pending: 0, expiryTimer: null };

  class ApiError extends Error {
    constructor(status, message) { super(message); this.status = status; }
  }

  async function api(method, path, body, { raw = false } = {}) {
    const headers = { Authorization: "Bearer " + state.token };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    let r;
    try {
      r = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch {
      throw new ApiError(0, "The server can't be reached. Check your connection.");
    }
    if (r.status === 401 && path !== "/me") {
      signOut("Your session has ended. Please sign in again.");
      throw new ApiError(401, "signed out");
    }
    if (raw && r.ok) return r;
    if (r.status === 204) return null;
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      let msg = data.detail;
      if (Array.isArray(msg)) msg = msg.map((d) => d.msg).join("; ");
      throw new ApiError(r.status, msg || r.statusText || "request failed");
    }
    return data;
  }

  const has = (role) => {
    const roles = state.me ? state.me.roles : [];
    if (role === "platform-admin") return roles.includes("platform-admin");
    return roles.includes(role) || roles.includes("admin");
  };

  // ---------------------------------------------------------------------------
  // Sign-in: OIDC authorization code with PKCE, dev token, or a pasted credential
  // ---------------------------------------------------------------------------
  const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  function randomString(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return b64url(a); }
  async function sha256(text) { return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))); }
  const redirectUri = () => location.origin + "/";

  async function startSSO() {
    const o = state.config.oidc;
    if (!window.crypto || !crypto.subtle) {
      throw new Error("Single sign-on needs a secure connection (HTTPS, or localhost).");
    }
    const verifier = randomString(48), st = randomString(16), nonce = randomString(16);
    store.set("pkce", JSON.stringify({ verifier, state: st, nonce, back: location.hash }));
    const params = new URLSearchParams({
      response_type: "code", client_id: o.client_id, redirect_uri: redirectUri(), scope: o.scopes,
      state: st, nonce, code_challenge: b64url(await sha256(verifier)), code_challenge_method: "S256",
      ...(o.extra_params || {}),
    });
    location.assign(o.authorization_endpoint + (o.authorization_endpoint.includes("?") ? "&" : "?") + params);
  }

  async function finishSSO(params) {
    const saved = JSON.parse(store.get("pkce") || "null");
    store.del("pkce");
    history.replaceState(null, "", location.pathname + (saved && saved.back ? saved.back : ""));
    if (params.get("error")) throw new Error(params.get("error_description") || params.get("error"));
    if (!saved || saved.state !== params.get("state")) {
      throw new Error("The sign-in response doesn't match this browser tab. Please sign in again.");
    }
    const o = state.config.oidc;
    const r = await fetch(o.token_endpoint, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code: params.get("code"),
        redirect_uri: redirectUri(), client_id: o.client_id, code_verifier: saved.verifier }),
    });
    const t = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(t.error_description || t.error || "The identity provider refused the sign-in.");
    if (t.id_token) {
      const c = jwtClaims(t.id_token);
      if (c && c.nonce !== undefined && c.nonce !== saved.nonce) throw new Error("Sign-in failed (nonce mismatch).");
      store.set("id_token", t.id_token);
    }
    const token = t[o.token];
    if (!token) throw new Error(`The identity provider didn't return an ${o.token}. Check OIDC_CONSOLE_TOKEN.`);
    return token;
  }

  async function signInWith(token) {
    state.token = token;
    let me;
    try {
      me = await api("GET", "/me");
    } catch (e) {
      state.token = null;
      throw new Error(e.status === 401 ? "That credential was not accepted." : e.message);
    }
    state.me = me;
    store.set("token", token);
    const claims = jwtClaims(token);
    clearTimeout(state.expiryTimer);
    if (claims && claims.exp) {
      const ms = claims.exp * 1000 - Date.now();
      state.expiryTimer = setTimeout(() => signOut("Your session has ended. Please sign in again."), Math.max(ms, 0));
    }
    connectEvents();
    renderShell();
  }

  function signOut(message) {
    const idToken = store.get("id_token");
    store.del("token"); store.del("id_token");
    clearTimeout(state.expiryTimer);
    if (state.ws) { state.ws.onclose = null; state.ws.close(); }
    state.ws = null; state.token = null; state.me = null; state.live = false;
    const o = state.config && state.config.oidc;
    if (!message && o && o.end_session_endpoint) {
      const p = new URLSearchParams({ client_id: o.client_id, post_logout_redirect_uri: redirectUri() });
      if (idToken) p.set("id_token_hint", idToken);
      location.assign(o.end_session_endpoint + (o.end_session_endpoint.includes("?") ? "&" : "?") + p);
      return;
    }
    renderSignIn(message);
  }

  function renderSignIn(message, isError) {
    const cfg = state.config || {};
    const err = h("div", { class: "notice" + (isError ? " error" : ""), text: message || "" });
    if (!message) err.classList.add("hidden");
    const fail = (e) => { err.textContent = e.message; err.className = "notice error"; };

    const ways = [];
    if (cfg.oidc && !cfg.oidc.error) {
      ways.push(h("button", { class: "btn block", id: "sso", onclick: () => startSSO().catch(fail) }, "Sign in with SSO"));
    } else if (cfg.oidc && cfg.oidc.error) {
      ways.push(h("div", { class: "notice error", text: cfg.oidc.error }));
    }
    if (cfg.dev_token) {
      ways.push(h("button", {
        class: "btn block" + (ways.length ? " secondary" : ""), id: "devToken",
        onclick: async () => {
          try {
            const r = await fetch("/dev/token", { method: "POST" });
            if (!r.ok) throw new Error("Dev tokens are only issued to this machine in development mode.");
            await signInWith((await r.json()).token);
          } catch (e) { fail(e); }
        },
      }, "Continue as local developer"));
    }
    const tokenBox = h("textarea", { id: "tokenInput", rows: "3", placeholder: "Paste an access token or an hrn_ API key", autocomplete: "off", spellcheck: "false" });
    const manual = h("form", {
      class: "stack", onsubmit: async (ev) => {
        ev.preventDefault();
        const v = tokenBox.value.trim();
        if (!v) return;
        try { await signInWith(v); } catch (e) { fail(e); }
      },
    }, tokenBox, h("button", { class: "btn secondary block", type: "submit" }, "Continue"));
    const other = ways.length
      ? [h("div", { class: "divider", text: "or" }), h("details", {}, h("summary", { text: "Use an access token or API key" }), manual)]
      : [manual];

    const hint = cfg.auth_mode === "oidc" && !cfg.oidc
      ? h("p", { class: "muted small", text: "Single sign-on for the console isn't configured (OIDC_CONSOLE_CLIENT_ID). Use a token from your identity provider or an API key." })
      : null;

    $("#app").replaceChildren(h("div", { class: "signin" }, h("div", { class: "card" },
      h("div", { class: "brand" }, h("span", { class: "mark", text: "H" }), "Harnis"),
      h("h1", { text: "Sign in" }),
      h("p", { class: "muted", text: "Agents with approvals, sandboxing and tenant isolation." }),
      h("div", { class: "stack signin-body" }, err, ...ways, ...other, hint),
      h("p", { class: "muted small" }, "API reference: ", h("a", { href: "/docs", text: "/docs" }),
        cfg.version ? ` · v${cfg.version}` : ""),
    )));
  }

  // ---------------------------------------------------------------------------
  // Live events (WebSocket)
  // ---------------------------------------------------------------------------
  const listeners = new Set();
  function connectEvents() {
    if (state.ws) { state.ws.onclose = null; state.ws.close(); }
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/v1/ws?token=${encodeURIComponent(state.token)}`);
    state.ws = ws;
    ws.onopen = () => setLive(true);
    ws.onmessage = (ev) => {
      let e;
      try { e = JSON.parse(ev.data); } catch { return; }
      if (e.type === "approval_required") {
        refreshPendingCount();
        if (has("reviewer")) toast(e.action && e.action.tool ? `Approval needed: ${e.action.tool}` : "An action is waiting for approval.");
      }
      for (const fn of listeners) { try { fn(e); } catch { /* view gone */ } }
    };
    ws.onclose = () => {
      setLive(false);
      if (state.token) setTimeout(() => state.token && state.ws === ws && connectEvents(), 3000);
    };
  }
  function setLive(on) {
    state.live = on;
    const dot = $("#liveDot");
    if (dot) { dot.className = "live" + (on ? " on" : ""); dot.title = on ? "Live updates connected" : "Live updates disconnected"; }
  }

  async function refreshPendingCount() {
    if (!has("reviewer")) return;
    try {
      state.pending = (await api("GET", "/v1/approvals")).length;
    } catch { return; }
    const b = $("#pendingBadge");
    if (b) { b.textContent = state.pending; b.classList.toggle("hidden", !state.pending); }
  }

  // ---------------------------------------------------------------------------
  // Shell and routing
  // ---------------------------------------------------------------------------
  const VIEWS = [
    { id: "chat", label: "Conversations", section: "Work", allowed: () => has("user"), render: viewChat },
    { id: "approvals", label: "Approvals", section: "Work", allowed: () => has("reviewer"), render: viewApprovals, badge: true },
    { id: "activity", label: "Usage & analytics", section: "Work", allowed: () => has("user") || has("reviewer"), render: viewActivity },
    { id: "agents", label: "Agents & prompts", section: "Work", allowed: () => has("user") || has("reviewer"), render: viewAgents },
    { id: "keys", label: "API keys", section: "Tenant admin", allowed: () => has("admin"), render: viewKeys },
    { id: "audit", label: "Audit log", section: "Tenant admin", allowed: () => has("admin"), render: viewAudit },
    { id: "data", label: "User data", section: "Tenant admin", allowed: () => has("admin"), render: viewUserData },
    { id: "tenants", label: "Tenants", section: "Platform", allowed: () => has("platform-admin"), render: viewTenants },
  ];

  function currentRoute() {
    const [id, arg] = location.hash.replace(/^#\/?/, "").split("/");
    const allowed = VIEWS.filter((v) => v.allowed());
    const view = allowed.find((v) => v.id === id) || allowed[0];
    return { view, arg: view && view.id === id ? decodeURIComponent(arg || "") : "" };
  }

  function renderShell() {
    const me = state.me;
    const nav = h("nav", { class: "nav", "aria-label": "Main" });
    let section = null;
    for (const v of VIEWS.filter((x) => x.allowed())) {
      if (v.section !== section) { section = v.section; nav.append(h("div", { class: "section", text: section })); }
      nav.append(h("a", { href: "#/" + v.id, "data-view": v.id }, v.label,
        v.badge ? h("span", { class: "badge hidden", id: "pendingBadge" }) : null));
    }
    const roles = me.roles.length ? me.roles : ["no roles"];
    $("#app").replaceChildren(h("div", { class: "shell" },
      h("header", { class: "topbar" },
        h("div", { class: "brand" }, h("span", { class: "mark", text: "H" }), "Harnis"),
        h("span", { class: "pill", title: "Tenant", text: me.tenant_id }),
        h("span", { class: "spacer" }),
        h("span", { class: "live", id: "liveDot" }),
        h("div", { class: "who" },
          h("span", { class: "name", title: `${me.user_id} (${me.via})`, text: me.user_id }),
          ...roles.map((r) => h("span", { class: "pill accent", text: r }))),
        h("button", { class: "btn ghost sm", id: "signOut", onclick: () => signOut() }, "Sign out")),
      nav,
      h("main", { class: "content", id: "content" })));
    setLive(state.live);
    refreshPendingCount();
    route();
  }

  let viewCleanup = null;
  function route() {
    if (!state.me) return;
    const { view, arg } = currentRoute();
    if (viewCleanup) { viewCleanup(); viewCleanup = null; }
    listeners.clear();
    for (const a of document.querySelectorAll(".nav a")) a.classList.toggle("active", view && a.dataset.view === view.id);
    const content = $("#content");
    if (!view) {
      content.replaceChildren(h("div", { class: "empty" },
        h("h2", { text: "No access yet" }),
        h("p", { text: "Your account has no Harnis roles in this tenant. Ask an administrator to grant you access." })));
      return;
    }
    content.replaceChildren();
    const result = view.render(content, arg);
    if (typeof result === "function") viewCleanup = result;
  }
  window.addEventListener("hashchange", route);

  function pageHead(title, subtitle, ...actions) {
    return h("div", { class: "page-head" },
      h("div", {}, h("h1", { text: title }), subtitle ? h("p", { class: "muted", text: subtitle }) : null),
      h("span", { class: "spacer" }), ...actions);
  }
  const errorBox = (e) => h("div", { class: "notice error", text: e.message || String(e) });

  // ---------------------------------------------------------------------------
  // Approval rendering (shared by conversations and the approvals page)
  // ---------------------------------------------------------------------------
  function diffBlock(diff) {
    const pre = h("pre", { class: "code diff" });
    for (const line of String(diff).split("\n")) {
      const cls = line.startsWith("+") && !line.startsWith("+++") ? "add"
        : line.startsWith("-") && !line.startsWith("---") ? "del" : line.startsWith("@@") ? "hunk" : null;
      pre.append(cls ? h("span", { class: cls, text: line }) : document.createTextNode(line + "\n"));
    }
    return pre;
  }

  function actionDetail(action) {
    const parts = [];
    const args = action.args || {};
    if (action.diff !== undefined) parts.push(action.diff ? diffBlock(action.diff) : h("p", { class: "muted", text: "(no changes)" }));
    if (args.command) parts.push(h("pre", { class: "code", text: "$ " + args.command }));
    const extra = Object.fromEntries(Object.entries(action).filter(([k]) => !["tool", "args", "diff"].includes(k)));
    if (Object.keys(extra).length) parts.push(h("pre", { class: "code", text: JSON.stringify(extra, null, 2) }));
    const shownArgs = Object.fromEntries(Object.entries(args).filter(([k]) =>
      !(k === "command" && args.command) && !((k === "content" || k === "path") && action.diff !== undefined)));
    if (Object.keys(shownArgs).length) parts.push(h("pre", { class: "code", text: JSON.stringify(shownArgs, null, 2) }));
    return parts;
  }

  function approvalCard(a, { onDone, showSession = true } = {}) {
    const msg = h("span", { class: "small" });
    const decide = async (approved, btn) => {
      btn.disabled = true;
      try {
        await api("POST", `/v1/approvals/${a.approval_id}/decision`, { approved, action_hash: a.action_hash });
        toast(approved ? "Approved. The agent continues." : "Denied.");
        refreshPendingCount();
        if (onDone) setTimeout(onDone, 500);
      } catch (e) {
        msg.textContent = e.message; msg.className = "small notice error"; btn.disabled = false;
      }
    };
    const canApprove = has("reviewer");
    const own = state.me && a.requested_by === state.me.user_id;
    const pending = !a.status || a.status === "pending";
    const yes = h("button", { class: "btn sm", onclick: (ev) => decide(true, ev.currentTarget) }, "Approve");
    const no = h("button", { class: "btn sm danger", onclick: (ev) => decide(false, ev.currentTarget) }, "Deny");
    return h("div", { class: "approval" },
      h("div", { class: "head" },
        h("strong", { text: a.action.tool }),
        a.status ? statusPill(a.status) : null,
        h("span", { class: "small", text: `requested by ${a.requested_by}` + (a.requested_at ? ` · ${ago(a.requested_at)}` : "") }),
        showSession ? h("a", { class: "small", href: `#/chat/${encodeURIComponent(a.session_id)}`, text: "open conversation" }) : null),
      h("div", { class: "body" }, actionDetail(a.action)),
      pending ? h("div", { class: "actions" },
        canApprove ? yes : null,
        (canApprove || own) ? no : null,
        !canApprove ? h("span", { class: "muted small", text: "Waiting for a reviewer to approve." }) : null,
        a.expires_at ? h("span", { class: "muted small", text: "expires " + fmtTime(a.expires_at) }) : null,
        msg) : null);
  }

  // ---------------------------------------------------------------------------
  // Conversations
  // ---------------------------------------------------------------------------
  function viewChat(root, sessionId) {
    let current = sessionId || store.get("session") || "";
    const list = h("div", { class: "list" });
    const messages = h("div", { class: "messages", id: "messages" });
    const head = h("div", { class: "conv-head" });
    const filesBox = h("div", { class: "files hidden" });
    const input = h("textarea", { id: "messageInput", rows: "1", placeholder: "Message the agents. Try: create calc.py with an add function" });
    const send = h("button", { class: "btn", id: "sendBtn" }, "Send");
    let busy = false;

    root.append(h("div", { class: "chat" },
      h("div", { class: "card sessions" },
        h("div", { class: "conv-head" }, h("h3", { text: "Conversations" }), h("span", { class: "spacer" }),
          h("button", { class: "btn sm", id: "newSession", onclick: () => newSession() }, "New")),
        list),
      h("div", { class: "card conv" }, head, messages, filesBox,
        h("div", { class: "composer" }, input, send))));

    async function loadList() {
      try {
        const rows = await api("GET", "/v1/sessions");
        list.replaceChildren(...(rows.length ? rows.map((s) => h("button", {
          class: "item" + (s.session_id === current ? " active" : ""), "data-session": s.session_id,
          onclick: () => select(s.session_id),
        }, h("div", { class: "row" }, h("span", { class: "mono", text: s.session_id.slice(0, 8) }), statusPill(s.status)),
          h("div", { class: "muted small", text: (s.user_id !== state.me.user_id ? s.user_id + " · " : "") + ago(s.updated_at) })))
          : [h("div", { class: "empty small", text: "No conversations yet." })]));
      } catch (e) { list.replaceChildren(errorBox(e)); }
    }

    // Switch conversations without rebuilding the view (replaceState fires no hashchange).
    function select(id, { load = true } = {}) {
      current = id;
      history.replaceState(null, "", "#/chat/" + encodeURIComponent(id));
      for (const b of list.querySelectorAll(".item")) b.classList.toggle("active", b.dataset.session === id);
      filesBox.classList.add("hidden");
      if (load) refresh();
    }

    async function newSession({ load = true } = {}) {
      try {
        const { session_id } = await api("POST", "/v1/sessions", {});
        select(session_id, { load });
        loadList();
        input.focus();
        return session_id;
      } catch (e) { toast(e.message, "error"); return null; }
    }

    function renderView(v) {
      const t = v.turn || {};
      head.replaceChildren(
        h("span", { class: "mono small", title: v.session_id, text: v.session_id.slice(0, 8) }),
        statusPill(v.status), v.agent ? h("span", { class: "pill", text: "agent: " + v.agent }) : null,
        h("span", { class: "spacer" }),
        t.steps != null ? h("span", { class: "muted small", text: `${t.steps} steps · ${t.tool_calls || 0} tools · ${money(t.cost_usd)}${t.cache_hit ? " · cached" : ""}` }) : null,
        h("button", { class: "btn ghost sm", id: "filesBtn", onclick: toggleFiles }, "Files"));
      const nodes = [];
      for (const m of v.messages) {
        if (m.role === "tool_call") nodes.push(h("div", { class: "msg tool", text: "→ " + m.text }));
        else nodes.push(h("div", { class: "msg " + (m.role === "user" ? "user" : "assistant"), text: m.text }));
      }
      if (v.flags && v.flags.length) nodes.push(h("div", { class: "msg system", text: "flags: " + v.flags.join(", ") }));
      if (v.status !== "completed" && v.status !== "awaiting_approval" && v.reply) {
        nodes.push(h("div", { class: "msg system", text: v.reply }));
      }
      messages.replaceChildren(...nodes);
      if (v.status === "awaiting_approval") showPendingApproval(v);
      messages.scrollTop = messages.scrollHeight;
    }

    function showPendingApproval(v) {
      const slot = h("div", {});
      messages.append(slot);
      if (v.approval) slot.replaceChildren(approvalCard(v.approval, { onDone: refresh, showSession: false }));
      messages.scrollTop = messages.scrollHeight;
    }

    async function refresh() {
      if (!current) {
        head.replaceChildren(h("span", { class: "muted", text: "Start a new conversation, or pick one from the list." }));
        messages.replaceChildren(h("div", { class: "empty" },
          h("h2", { text: "What should the agents do?" }),
          h("p", { class: "muted", text: "Questions go to the support agent; anything about code goes to the coding agent. Changes to files and commands wait for an approval." })));
        return;
      }
      try {
        renderView(await api("GET", "/v1/sessions/" + encodeURIComponent(current)));
        store.set("session", current);
        if (!filesBox.classList.contains("hidden")) loadFiles();
      } catch (e) {
        if (e.status === 404) { store.del("session"); current = ""; refresh(); return; }
        messages.replaceChildren(errorBox(e));
      }
    }

    async function loadFiles() {
      try {
        const files = await api("GET", `/v1/sessions/${encodeURIComponent(current)}/files`);
        const names = Object.keys(files).sort();
        const viewer = h("pre", { class: "code hidden" });
        filesBox.replaceChildren(h("div", { class: "row" }, h("h3", { text: "Workspace files" }),
          h("span", { class: "muted small", text: names.length ? `${names.length} file(s)` : "empty" })),
          h("div", { class: "row" }, ...names.map((n) => h("button", { class: "file", onclick: () => {
            viewer.textContent = files[n]; viewer.classList.remove("hidden");
          } }, n))), viewer);
      } catch (e) { filesBox.replaceChildren(errorBox(e)); }
    }
    function toggleFiles() {
      if (!current) return;
      filesBox.classList.toggle("hidden");
      if (!filesBox.classList.contains("hidden")) loadFiles();
    }

    async function sendMessage() {
      const text = input.value.trim();
      if (!text || busy) return;
      busy = true; send.disabled = true;
      if (!current) {
        current = await newSession({ load: false }) || "";
        messages.replaceChildren();
        if (!current) { busy = false; send.disabled = false; return; }
      }
      input.value = "";
      messages.append(h("div", { class: "msg user", text }), h("div", { class: "msg system", id: "thinking", text: "Working..." }));
      messages.scrollTop = messages.scrollHeight;
      try {
        renderView(await api("POST", `/v1/sessions/${encodeURIComponent(current)}/turns`, { message: text }));
        loadList();
      } catch (e) {
        const t = $("#thinking"); if (t) t.remove();
        messages.append(h("div", { class: "msg system", text: e.message }));
        if (e.status === 429) toast("You're sending messages too quickly. Wait a moment and try again.", "error");
      } finally { busy = false; send.disabled = false; input.focus(); }
    }

    send.addEventListener("click", sendMessage);
    input.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } });

    let pending = null;
    listeners.add((e) => {
      if (e.session_id && e.session_id === current && ["turn_complete", "tool_result", "approval_required"].includes(e.type) && !busy) {
        clearTimeout(pending); pending = setTimeout(() => { refresh(); loadList(); }, 250);
      }
    });
    loadList(); refresh();
    input.focus();
  }

  // ---------------------------------------------------------------------------
  // Approvals
  // ---------------------------------------------------------------------------
  function viewApprovals(root) {
    let status = "pending";
    const body = h("div", { class: "stack" });
    const tabs = h("div", { class: "row" }, ...["pending", "approved", "denied", "expired"].map((s) =>
      h("button", { class: "btn sm " + (s === status ? "" : "secondary"), "data-status": s, onclick: () => { status = s; load(); } }, s)));
    root.append(pageHead("Approvals", "Every file change and command an agent proposes waits here for a reviewer. Approvals are bound to the exact action shown."), tabs, h("div", { class: "spacer" }), body);
    body.classList.add("stack");
    async function load() {
      for (const b of tabs.children) b.className = "btn sm " + (b.dataset.status === status ? "" : "secondary");
      try {
        const rows = await api("GET", "/v1/approvals?status=" + status);
        body.replaceChildren(...(rows.length ? rows.map((a) => approvalCard(a, { onDone: load }))
          : [h("div", { class: "card empty", text: status === "pending" ? "Nothing is waiting for approval." : `No ${status} approvals.` })]));
      } catch (e) { body.replaceChildren(errorBox(e)); }
    }
    listeners.add((e) => { if (e.type === "approval_required" && status === "pending") load(); });
    body.style.setProperty("margin-top", "12px");
    load();
  }

  // ---------------------------------------------------------------------------
  // Usage and analytics
  // ---------------------------------------------------------------------------
  function table(columns, rows, empty) {
    if (!rows.length) return h("div", { class: "empty", text: empty });
    return h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ...columns.map((c) => h("th", { class: c.num ? "num" : null, text: c.label })))),
      h("tbody", {}, ...rows.map((r) => h("tr", {}, ...columns.map((c) => {
        const v = c.render ? c.render(r) : r[c.key];
        return h("td", { class: c.num ? "num" : null }, v instanceof Node ? v : String(v ?? ""));
      }))))));
  }

  async function viewActivity(root) {
    root.append(pageHead("Usage & analytics", "Tokens and cost for your tenant, and how turns went in the last 24 hours."));
    const usageCard = h("div", { class: "card" }, h("div", { class: "conv-head" }, h("h2", { text: "Usage by model" })));
    root.append(usageCard);
    try {
      const rows = await api("GET", "/v1/usage");
      const total = rows.reduce((a, r) => a + Number(r.cost_usd || 0), 0);
      usageCard.append(table([
        { label: "Provider", key: "provider" }, { label: "Model", key: "model" },
        { label: "Calls", num: true, render: (r) => num(r.calls) },
        { label: "Input tokens", num: true, render: (r) => num(r.input_tokens) },
        { label: "Output tokens", num: true, render: (r) => num(r.output_tokens) },
        { label: "Cost", num: true, render: (r) => money(r.cost_usd) },
      ], rows, "No model calls yet."));
      if (rows.length) usageCard.append(h("div", { class: "conv-head" }, h("span", { class: "spacer" }), h("strong", { text: "Total " + money(total) })));
    } catch (e) { usageCard.append(errorBox(e)); }

    if (has("admin")) {
      const card = h("div", { class: "card", id: "pricingCard" }, h("div", { class: "conv-head" }, h("h2", { text: "Model prices" }),
        h("span", { class: "muted small", text: "USD per million tokens; used for costs and budgets" })));
      card.style.setProperty("margin-top", "16px");
      root.append(card);
      try {
        const p = await api("GET", "/v1/admin/pricing");
        if (!p.all_confirmed) {
          card.append(h("div", { class: "notice", text: "Some prices are not confirmed by the operator, so costs and budgets may be wrong. The operator sets them with `python tasks.py pricing` (PRICING_OVERRIDES)." }));
        }
        card.append(table([
          { label: "Model", render: (r) => h("span", { class: "mono", text: r.model }) },
          { label: "Input", num: true, render: (r) => r.input_usd_per_mtok == null ? "" : "$" + r.input_usd_per_mtok },
          { label: "Output", num: true, render: (r) => r.output_usd_per_mtok == null ? "" : "$" + r.output_usd_per_mtok },
          { label: "Status", render: (r) => statusPill(r.confirmed ? "confirmed" : "unconfirmed") },
        ], p.models, "No models configured."));
      } catch (e) { card.append(errorBox(e)); }
    }

    if (has("reviewer")) {
      const card = h("div", { class: "card" }, h("div", { class: "conv-head" }, h("h2", { text: "Last 24 hours" }),
        h("span", { class: "muted small", text: "refreshed hourly by the maintenance job" })));
      card.style.setProperty("margin-top", "16px");
      root.append(card);
      try {
        const rows = await api("GET", "/v1/analytics");
        const max = Math.max(1, ...rows.map((r) => r.runs || 0));
        card.append(table([
          { label: "Hour", render: (r) => fmtTime(r.hour) },
          { label: "Runs", render: (r) => { const b = h("div", { class: "bar", title: String(r.runs) }); b.style.setProperty("width", `${Math.round((r.runs / max) * 120)}px`); return h("div", { class: "row" }, b, String(r.runs)); } },
          { label: "Avg latency", num: true, render: (r) => r.avg_latency_ms == null ? "" : Math.round(r.avg_latency_ms) + " ms" },
          { label: "Cache hits", num: true, render: (r) => r.cache_hit_pct == null ? "" : Math.round(r.cache_hit_pct) + "%" },
          { label: "Success", num: true, render: (r) => r.success_pct == null ? "" : Math.round(r.success_pct) + "%" },
          { label: "Halted", num: true, key: "halted" },
        ], rows, "No data yet. Run `python tasks.py maintenance` (or wait for the hourly job) to refresh analytics."));
      } catch (e) { card.append(errorBox(e)); }
    }
  }

  // ---------------------------------------------------------------------------
  // Agents and prompts
  // ---------------------------------------------------------------------------
  async function viewAgents(root) {
    root.append(pageHead("Agents & prompts", has("admin")
      ? "The agents available in this deployment. As a tenant admin you can change the prompt each one uses for your tenant."
      : "The agents available in this deployment and the tools each may use."));
    const grid = h("div", { class: "grid" });
    root.append(grid);
    let agents;
    try { agents = await api("GET", "/v1/agents"); } catch (e) { grid.append(errorBox(e)); return; }
    const cards = agents.map((a) => ({ key: a.name, title: a.name, description: a.description, isDefault: a.default, tools: a.tools }));
    if (has("admin")) cards.push({ key: "router", title: "router", description: "Chooses which agent handles each new message." });
    for (const c of cards) {
      const editor = h("div", { class: "stack hidden" });
      const card = h("div", { class: "card pad stack", "data-agent": c.key },
        h("div", { class: "row" }, h("h2", { text: c.title }), c.isDefault ? h("span", { class: "pill accent", text: "default" }) : null),
        h("p", { class: "muted", text: c.description }),
        c.tools ? h("div", { class: "tools" }, ...c.tools.map((t) => h("span", { class: "pill " + (t.risk === "high" ? "warn" : ""), title: t.risk === "high" ? "needs approval" : "runs without approval", text: t.name }))) : null,
        has("admin") ? h("div", { class: "row" }, h("button", { class: "btn secondary sm", onclick: () => openEditor(c.key, editor) }, "Edit prompt")) : null,
        editor);
      grid.append(card);
    }

    async function openEditor(key, box) {
      if (!box.classList.contains("hidden")) { box.classList.add("hidden"); return; }
      box.classList.remove("hidden");
      box.replaceChildren(h("p", { class: "muted small", text: "Loading..." }));
      try {
        const p = await api("GET", "/v1/prompts/" + encodeURIComponent(key));
        const ta = h("textarea", { rows: "10", class: "mono" });
        ta.value = p.text;
        const info = h("span", { class: "muted small", text: p.version ? `version ${p.version}` : "built-in default" });
        const save = h("button", { class: "btn sm", onclick: async () => {
          save.disabled = true;
          try {
            const r = await api("POST", "/v1/prompts", { key, text: ta.value });
            info.textContent = `saved as version ${r.version}`;
            toast(`Prompt for ${key} saved (version ${r.version}). New turns use it.`);
          } catch (e) { toast(e.message, "error"); } finally { save.disabled = false; }
        } }, "Save new version");
        box.replaceChildren(ta, h("div", { class: "row" }, save, info));
      } catch (e) { box.replaceChildren(errorBox(e)); }
    }
  }

  // ---------------------------------------------------------------------------
  // API keys
  // ---------------------------------------------------------------------------
  function viewKeys(root) {
    root.append(pageHead("API keys", "Keys for scripts, CI jobs and integrations in this tenant. A key is shown once, when it is created."));
    const name = h("input", { type: "text", id: "keyName", placeholder: "e.g. ci-pipeline", maxlength: "100" });
    const days = h("input", { type: "number", id: "keyDays", min: "1", max: "3650", placeholder: "never" });
    const roleBoxes = ["user", "reviewer", "admin"].map((r) => h("input", { type: "checkbox", value: r, checked: r === "user" }));
    const created = h("div", {});
    const listBox = h("div", { class: "card" });
    const form = h("form", { class: "card pad stack", onsubmit: async (ev) => {
      ev.preventDefault();
      const roles = roleBoxes.filter((b) => b.checked).map((b) => b.value);
      if (!name.value.trim() || !roles.length) { toast("Give the key a name and at least one role.", "error"); return; }
      try {
        const r = await api("POST", "/v1/admin/api-keys", { name: name.value.trim(), roles,
          expires_in_days: days.value ? Number(days.value) : null });
        name.value = ""; days.value = "";
        const code = h("code", { id: "newKey", text: r.key });
        created.replaceChildren(h("div", { class: "notice ok stack" },
          h("strong", { text: `Key "${r.name}" created. Copy it now; it won't be shown again.` }),
          h("div", { class: "secret" }, code, h("button", { class: "btn sm", type: "button", onclick: async () => {
            try { await navigator.clipboard.writeText(r.key); toast("Copied."); } catch { toast("Select the key and copy it manually.", "error"); }
          } }, "Copy"))));
        load();
      } catch (e) { toast(e.message, "error"); }
    } },
      h("h2", { text: "Create a key" }),
      h("div", { class: "row" },
        h("label", { class: "field spacer" }, "Name", name),
        h("label", { class: "field" }, "Expires after (days)", days)),
      h("div", { class: "row" }, h("span", { class: "muted small", text: "Roles:" }),
        ...roleBoxes.map((b) => h("label", { class: "check" }, b, b.value))),
      h("div", { class: "row" }, h("button", { class: "btn", type: "submit", id: "createKey" }, "Create key")),
      created);
    listBox.style.setProperty("margin-top", "16px");
    root.append(form, listBox);

    async function load() {
      try {
        const rows = await api("GET", "/v1/admin/api-keys");
        listBox.replaceChildren(table([
          { label: "Name", key: "name" },
          { label: "Key id", render: (r) => h("span", { class: "mono", text: r.key_id }) },
          { label: "Roles", render: (r) => r.roles.join(", ") },
          { label: "Created", render: (r) => `${fmtTime(r.created_at)} by ${r.created_by}` },
          { label: "Expires", render: (r) => r.expires_at ? fmtTime(r.expires_at) : "never" },
          { label: "Last used", render: (r) => r.last_used_at ? ago(r.last_used_at) : "never" },
          { label: "Status", render: (r) => statusPill(r.revoked_at ? "revoked" : (r.expires_at && new Date(r.expires_at) < new Date() ? "expired" : "active")) },
          { label: "", render: (r) => r.revoked_at ? "" : revokeButton(r) },
        ], rows, "No API keys yet."));
      } catch (e) { listBox.replaceChildren(errorBox(e)); }
    }
    function revokeButton(r) {
      const b = h("button", { class: "btn sm secondary", "data-revoke": r.key_id }, "Revoke");
      b.addEventListener("click", async () => {
        if (b.dataset.confirm !== "1") { b.dataset.confirm = "1"; b.textContent = "Confirm revoke"; b.className = "btn sm danger"; return; }
        try { await api("DELETE", "/v1/admin/api-keys/" + encodeURIComponent(r.key_id)); toast("Key revoked."); load(); }
        catch (e) { toast(e.message, "error"); }
      });
      return b;
    }
    load();
  }

  // ---------------------------------------------------------------------------
  // Audit log
  // ---------------------------------------------------------------------------
  function viewAudit(root) {
    const filter = h("input", { type: "text", id: "auditFilter", placeholder: "event type, e.g. approval_decided" });
    const tbody = h("tbody", {});
    const more = h("button", { class: "btn secondary sm hidden", onclick: () => load(false) }, "Load more");
    let after = 0;
    root.append(pageHead("Audit log", "Security-relevant events in this tenant, oldest first. Append-only.",
      h("button", { class: "btn secondary sm", id: "downloadAudit", onclick: download }, "Download NDJSON")));
    root.append(h("form", { class: "row", onsubmit: (ev) => { ev.preventDefault(); load(true); } },
      h("div", { class: "spacer" }, filter), h("button", { class: "btn sm", type: "submit" }, "Filter")));
    const card = h("div", { class: "card table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ...["#", "Time", "Actor", "Event", "Session", "Detail"].map((t) => h("th", { text: t })))), tbody));
    card.style.setProperty("margin-top", "12px");
    root.append(card, h("div", { class: "row" }, more));

    const q = () => (filter.value.trim() ? "&event_type=" + encodeURIComponent(filter.value.trim()) : "");
    async function load(reset) {
      if (reset) { after = 0; tbody.replaceChildren(); }
      try {
        const r = await api("GET", `/v1/admin/audit?limit=100&after=${after}${q()}`);
        for (const e of r.events) {
          tbody.append(h("tr", {},
            h("td", { class: "num", text: e.event_id }), h("td", { text: fmtTime(e.created_at) }),
            h("td", { text: e.actor || "" }), h("td", {}, h("span", { class: "pill", text: e.event_type })),
            h("td", {}, e.session_id ? h("a", { class: "mono", href: "#/chat/" + encodeURIComponent(e.session_id), text: e.session_id.slice(0, 8) }) : ""),
            h("td", {}, h("span", { class: "detail mono", title: JSON.stringify(e.detail), text: JSON.stringify(e.detail) }))));
        }
        if (!tbody.children.length) tbody.append(h("tr", {}, h("td", { colspan: "6", class: "empty", text: "No events." })));
        after = r.next_after;
        more.classList.toggle("hidden", r.events.length < 100);
      } catch (e) { tbody.replaceChildren(h("tr", {}, h("td", { colspan: "6" }, errorBox(e)))); }
    }
    async function download() {
      try {
        const r = await api("GET", `/v1/admin/audit?format=ndjson&limit=5000${q()}`, undefined, { raw: true });
        const url = URL.createObjectURL(await r.blob());
        const a = h("a", { href: url, download: `harnis-audit-${state.me.tenant_id}.ndjson` });
        document.body.append(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch (e) { toast(e.message, "error"); }
    }
    load(true);
  }

  // ---------------------------------------------------------------------------
  // User data: export and erasure (tenant admin)
  // ---------------------------------------------------------------------------
  function viewUserData(root) {
    root.append(pageHead("User data", "Export everything Harnis stores about a person in this tenant, or erase it. Erasure deletes their conversations and files and replaces their id in retained history with a pseudonym. It can't be undone."));
    const user = h("input", { type: "text", id: "dataUser", placeholder: "user id, as shown in conversations and the audit log" });
    const out = h("div", { class: "stack" });
    const exportBtn = h("button", { class: "btn secondary", id: "exportUser", type: "button", onclick: async () => {
      const id = user.value.trim(); if (!id) return;
      try {
        const data = await api("GET", `/v1/admin/users/${encodeURIComponent(id)}/export`);
        const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
        const a = h("a", { href: url, download: `harnis-export-${state.me.tenant_id}-${id}.json` });
        document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
        out.replaceChildren(h("div", { class: "notice ok", text: `Exported ${data.sessions.length} conversation(s), ${data.approvals.length} approval(s), ${data.audit_events.length} audit event(s).` }));
      } catch (e) { out.replaceChildren(errorBox(e)); }
    } }, "Export (JSON)");
    const eraseBtn = h("button", { class: "btn danger", id: "eraseUser", type: "button", onclick: () => {
      const id = user.value.trim(); if (!id) return;
      const confirmBox = h("input", { type: "text", id: "eraseConfirm", placeholder: `type ${id} to confirm` });
      const go = h("button", { class: "btn danger", id: "eraseConfirmBtn", type: "button", onclick: async () => {
        if (confirmBox.value !== id) { toast("Type the user id exactly to confirm.", "error"); return; }
        try {
          const r = await api("DELETE", `/v1/admin/users/${encodeURIComponent(id)}/data?confirm=${encodeURIComponent(id)}`);
          out.replaceChildren(h("div", { class: "notice ok", text: `Erased: ${r.deleted_sessions} conversation(s) deleted, ${r.pseudonymized_audit_events} audit event(s) now show ${r.alias}.` }));
        } catch (e) { out.replaceChildren(errorBox(e)); }
      } }, "Erase permanently");
      out.replaceChildren(h("div", { class: "notice error stack" }, h("strong", { text: `Erase all data of ${id} in ${state.me.tenant_id}?` }), confirmBox, h("div", { class: "row" }, go)));
    } }, "Erase...");
    root.append(h("div", { class: "card pad stack" }, h("label", { class: "field" }, "User id", user), h("div", { class: "row" }, exportBtn, eraseBtn), out));
  }

  // ---------------------------------------------------------------------------
  // Tenants (platform-admin)
  // ---------------------------------------------------------------------------
  function viewTenants(root) {
    root.append(pageHead("Tenants", "Each tenant's data is isolated by the database. Disabling a tenant locks out its users and API keys immediately."));
    const listBox = h("div", { class: "card" });
    const formBox = h("div", {});
    root.append(h("div", { class: "row" }, h("button", { class: "btn", id: "newTenant", onclick: () => edit(null) }, "New tenant")), formBox, listBox);
    listBox.style.setProperty("margin-top", "16px");

    function edit(t) {
      const id = h("input", { type: "text", id: "tenantId", placeholder: "acme", disabled: !!t });
      const nm = h("input", { type: "text", id: "tenantName", placeholder: "Acme Corp" });
      const prov = h("input", { type: "text", id: "tenantProviders", placeholder: "* (all configured providers)" });
      const cap = h("input", { type: "number", id: "tenantCap", min: "0", step: "0.01", placeholder: "platform default" });
      const active = h("input", { type: "checkbox", id: "tenantActive", checked: t ? t.active : true });
      if (t) { id.value = t.tenant_id; nm.value = t.name || ""; prov.value = (t.allowed_providers || []).join(", "); cap.value = t.max_cost_usd_per_turn ?? ""; }
      const form = h("form", { class: "card pad stack", onsubmit: async (ev) => {
        ev.preventDefault();
        const tid = id.value.trim();
        if (!tid) { toast("Enter a tenant id.", "error"); return; }
        const body = { name: nm.value.trim() || null, active: active.checked,
          allowed_providers: prov.value.trim() ? prov.value.split(",").map((s) => s.trim()).filter(Boolean) : (t ? null : ["*"]),
          max_cost_usd_per_turn: cap.value === "" ? (t && t.max_cost_usd_per_turn != null ? 0 : null) : Number(cap.value) };
        try {
          await api("PUT", "/v1/admin/tenants/" + encodeURIComponent(tid), body);
          toast(`Tenant ${tid} saved.`); formBox.replaceChildren(); load();
        } catch (e) { toast(e.message, "error"); }
      } },
        h("h2", { text: t ? `Edit ${t.tenant_id}` : "New tenant" }),
        h("div", { class: "row" }, h("label", { class: "field spacer" }, "Tenant id", id), h("label", { class: "field spacer" }, "Name", nm)),
        h("div", { class: "row" }, h("label", { class: "field spacer" }, "Allowed model providers (comma-separated)", prov),
          h("label", { class: "field" }, "Max cost per turn (USD)", cap)),
        h("label", { class: "check" }, active, "Active"),
        h("div", { class: "row" }, h("button", { class: "btn", type: "submit", id: "saveTenant" }, "Save"),
          h("button", { class: "btn secondary", type: "button", onclick: () => formBox.replaceChildren() }, "Cancel")));
      form.style.setProperty("margin-top", "12px");
      formBox.replaceChildren(form);
    }

    function remove(t) {
      const box = h("input", { type: "text", id: "deleteConfirm", placeholder: `type ${t.tenant_id} to confirm` });
      const go = h("button", { class: "btn danger", id: "deleteTenantBtn", type: "button", onclick: async () => {
        if (box.value !== t.tenant_id) { toast("Type the tenant id exactly to confirm.", "error"); return; }
        try {
          const r = await api("DELETE", `/v1/admin/tenants/${encodeURIComponent(t.tenant_id)}?confirm=${encodeURIComponent(t.tenant_id)}`);
          toast(`Tenant ${t.tenant_id} deleted (${r.deleted_sessions} conversations).`); formBox.replaceChildren(); load();
        } catch (e) { toast(e.message, "error"); }
      } }, "Delete permanently");
      const card = h("div", { class: "notice error stack" },
        h("strong", { text: `Delete tenant ${t.tenant_id} and all its data? Conversations, files, approvals, prompts, API keys, usage and its audit log are removed. This can't be undone.` }),
        box, h("div", { class: "row" }, go, h("button", { class: "btn secondary", type: "button", onclick: () => formBox.replaceChildren() }, "Cancel")));
      card.style.setProperty("margin-top", "12px");
      formBox.replaceChildren(card);
    }

    async function load() {
      try {
        const rows = await api("GET", "/v1/admin/tenants");
        listBox.replaceChildren(table([
          { label: "Tenant", render: (r) => h("span", { class: "mono", text: r.tenant_id }) },
          { label: "Name", key: "name" },
          { label: "Providers", render: (r) => (r.allowed_providers || []).join(", ") },
          { label: "Max cost / turn", num: true, render: (r) => r.max_cost_usd_per_turn == null ? "default" : "$" + r.max_cost_usd_per_turn },
          { label: "Status", render: (r) => statusPill(r.active ? "active" : "disabled") },
          { label: "Created", render: (r) => fmtTime(r.created_at) },
          { label: "", render: (r) => h("div", { class: "row" },
              h("button", { class: "btn sm secondary", "data-edit": r.tenant_id, onclick: () => edit(r) }, "Edit"),
              r.active ? null : h("button", { class: "btn sm danger", "data-delete": r.tenant_id, onclick: () => remove(r) }, "Delete...")) },
        ], rows, "No tenants."));
      } catch (e) { listBox.replaceChildren(errorBox(e)); }
    }
    load();
  }
  STATUS_KIND.active = "ok"; STATUS_KIND.disabled = "danger"; STATUS_KIND.revoked = "danger";
  STATUS_KIND.confirmed = "ok"; STATUS_KIND.unconfirmed = "warn";

  // ---------------------------------------------------------------------------
  // Start
  // ---------------------------------------------------------------------------
  async function boot() {
    try {
      const r = await fetch("/v1/auth/config");
      state.config = await r.json();
    } catch {
      $("#app").replaceChildren(h("div", { class: "boot", text: "The Harnis API can't be reached." }));
      return;
    }
    const params = new URLSearchParams(location.search);
    if (params.has("code") || params.has("error")) {
      try { await signInWith(await finishSSO(params)); } catch (e) { renderSignIn(e.message, true); }
      return;
    }
    const saved = store.get("token");
    if (saved) {
      try { await signInWith(saved); return; } catch { store.del("token"); }
    }
    renderSignIn();
  }
  boot();
})();

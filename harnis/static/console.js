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
  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
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
  // Plain wording for people who are not operators.
  const STATUS_LABEL = {
    completed: "Done", awaiting_approval: "Waiting for approval", running: "Working", failed: "Stopped with an error",
    rejected: "Blocked", escalated: "Passed to a person", pending: "Waiting", idle: "Ready",
  };
  const statusText = (s) => STATUS_LABEL[s] || (String(s || "").replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase()));
  const statusPill = (s) => h("span", { class: "pill " + (STATUS_KIND[s] || ""), text: statusText(s) });

  // ---------------------------------------------------------------------------
  // Branding (name, logo, colours, help link come from the public config)
  // ---------------------------------------------------------------------------
  const brand = () => (state.config && state.config.brand) || { name: "Harnis" };
  function brandBlock() {
    const b = brand();
    const mark = b.logo
      ? h("img", { class: "logo", src: "/console/logo", alt: "" })
      : h("span", { class: "mark", text: (b.name || "H").charAt(0).toUpperCase() });
    return h("div", { class: "brand" }, mark, b.name);
  }
  function helpLink() {
    const b = brand();
    return b.help_url ? h("a", { class: "help", href: b.help_url, target: "_blank", rel: "noopener noreferrer", text: "Help" }) : null;
  }
  function applyBrand() {
    const b = brand();
    document.title = b.name || "Harnis";
    const dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)");
    const root = document.documentElement.style;
    const apply = () => {
      const hex = (dark && dark.matches && b.accent_dark) || b.accent;
      if (!hex) { for (const k of ["--accent", "--accent-ink", "--accent-soft"]) root.removeProperty(k); return; }
      const [r, g, bl] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
      const lum = (0.2126 * r + 0.7152 * g + 0.0722 * bl) / 255;
      root.setProperty("--accent", hex);
      root.setProperty("--accent-ink", lum > 0.6 ? "#111111" : "#ffffff");
      root.setProperty("--accent-soft", `color-mix(in srgb, ${hex} 14%, var(--surface))`);
    };
    apply();
    if (dark && dark.addEventListener) dark.addEventListener("change", apply);
  }

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
      brandBlock(),
      h("h1", { text: "Sign in" }),
      h("p", { class: "muted", text: "Agents with approvals, sandboxing and tenant isolation." }),
      h("div", { class: "stack signin-body" }, err, ...ways, ...other, hint),
      h("p", { class: "muted small" }, "API reference: ", h("a", { href: "/docs", text: "/docs" }),
        cfg.version ? ` · v${cfg.version}` : ""),
      helpLink() ? h("p", { class: "small" }, helpLink()) : null,
    )));
  }

  // ---------------------------------------------------------------------------
  // Live events (WebSocket)
  // ---------------------------------------------------------------------------
  const listeners = new Set();
  function connectEvents() {
    if (state.ws) { state.ws.onclose = null; state.ws.close(); }
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/v1/ws`);
    state.ws = ws;
    // The token goes in the first message, never in the URL (URLs are logged).
    ws.onopen = () => { ws.send(JSON.stringify({ type: "auth", token: state.token })); setLive(true); state.wsBackoff = 0; };
    ws.onmessage = (ev) => {
      let e;
      try { e = JSON.parse(ev.data); } catch { return; }
      if (e.type === "approval_required") {
        refreshPendingCount();
        if (has("reviewer")) alertNewApproval(e);
        if (has("reviewer")) toast(e.action && e.action.tool ? `Approval needed: ${e.action.tool}` : "An action is waiting for approval.");
      }
      for (const fn of listeners) { try { fn(e); } catch { /* view gone */ } }
    };
    ws.onclose = (ev) => {
      setLive(false);
      if (state.ws !== ws || !state.token) return;
      // The server re-checks the credential while connected: 4401 = expired or
      // revoked, 4403 = the organization (tenant) was disabled. Retrying can't help.
      if (ev.code === 4401) { signOut("Your session has ended. Please sign in again."); return; }
      if (ev.code === 4403) { signOut("Your organization's access has been disabled. Contact your administrator."); return; }
      // Anything else (network drop, server restart, a refused handshake): confirm
      // the sign-in is still good, then reconnect with a growing delay (3 s to 60 s).
      const delay = Math.min(60000, 3000 * 2 ** (state.wsBackoff || 0));
      state.wsBackoff = Math.min((state.wsBackoff || 0) + 1, 5);
      setTimeout(async () => {
        if (!state.token || state.ws !== ws) return;
        try {
          const r = await fetch("/me", { headers: { Authorization: "Bearer " + state.token } });
          if (r.status === 401) { signOut("Your session has ended. Please sign in again."); return; }
        } catch { /* server unreachable: try the stream anyway, it backs off */ }
        if (state.token && state.ws === ws) connectEvents();
      }, delay);
    };
  }
  function setLive(on) {
    state.live = on;
    const dot = $("#liveDot");
    if (dot) { dot.className = "live" + (on ? " on" : ""); dot.title = on ? "Live updates connected" : "Live updates disconnected"; }
  }

  // A new approval while this tab is in the background: flash the title and, if the reviewer
  // allowed it, show a desktop notification. Both stop when they come back to the tab.
  function alertNewApproval(e) {
    if (!document.hidden) return;
    state.unseen = (state.unseen || 0) + 1;
    document.title = `(${state.unseen}) Approval needed · ${brand().name || "Harnis"}`;
    try {
      if ("Notification" in window && Notification.permission === "granted") {
        const tool = e.action && e.action.tool ? e.action.tool : "an action";
        const n = new Notification("Approval needed", { body: `${e.requested_by || "Someone"} wants to run ${tool}`, tag: "harnis-approval" });
        n.onclick = () => { window.focus(); location.hash = "#/approvals"; n.close(); };
      }
    } catch { /* notifications are optional */ }
  }
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.unseen) { state.unseen = 0; document.title = brand().name || "Harnis"; }
  });

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
    { id: "start", label: "Start", section: "Work", allowed: () => has("user"), render: viewStart },
    { id: "chat", label: "Conversations", section: "Work", allowed: () => has("user"), render: viewChat },
    { id: "approvals", label: "Approvals", section: "Work", allowed: () => has("reviewer"), render: viewApprovals, badge: true },
    { id: "activity", label: "Usage & analytics", section: "Work", allowed: () => has("user") || has("reviewer"), render: viewActivity },
    { id: "agents", label: "Agents & prompts", section: "Work", allowed: () => has("user") || has("reviewer"), render: viewAgents },
    { id: "schedules", label: "Schedules", section: "Work", allowed: () => has("user"), render: viewSchedules },
    { id: "keys", label: "API keys", section: "Tenant admin", allowed: () => has("admin"), render: viewKeys },
    { id: "audit", label: "Audit log", section: "Tenant admin", allowed: () => has("admin"), render: viewAudit },
    { id: "data", label: "User data", section: "Tenant admin", allowed: () => has("admin"), render: viewUserData },
    { id: "tenants", label: "Tenants", section: "Platform", allowed: () => has("platform-admin"), render: viewTenants },
  ];

  function currentRoute() {
    const [id, arg] = location.hash.replace(/^#\/?/, "").split("/");
    const allowed = VIEWS.filter((v) => v.allowed());
    // People who only hold the user role land on Start; reviewers and admins keep Conversations.
    const plain = !has("reviewer") && !has("platform-admin");
    const landing = (plain && allowed.find((v) => v.id === "start")) || allowed.find((v) => v.id !== "start") || allowed[0];
    const view = allowed.find((v) => v.id === id) || landing;
    return { view, arg: view && view.id === id ? decodeURIComponent(arg || "") : "" };
  }

  function renderShell() {
    const me = state.me;
    const nav = h("nav", { class: "nav", id: "mainNav", "aria-label": "Main" });
    let section = null;
    for (const v of VIEWS.filter((x) => x.allowed())) {
      if (v.section !== section) { section = v.section; nav.append(h("div", { class: "section", text: section })); }
      nav.append(h("a", { href: "#/" + v.id, "data-view": v.id }, v.label,
        v.badge ? h("span", { class: "badge hidden", id: "pendingBadge" }) : null));
    }
    const roles = me.roles.length ? me.roles : ["no roles"];
    const narrow = () => window.matchMedia("(max-width: 860px)").matches;
    const menuBtn = h("button", { class: "btn ghost sm menu-btn", id: "menuToggle", type: "button", "aria-controls": "mainNav",
      "aria-expanded": "true", "aria-label": "Menu", onclick: () => setMenu(shell.classList.contains("nav-closed")) }, "\u2630");
    function setMenu(open, remember = true) {
      shell.classList.toggle("nav-closed", !open);
      menuBtn.setAttribute("aria-expanded", String(open));
      if (remember && !narrow()) { try { localStorage.setItem("harnis.nav", open ? "open" : "closed"); } catch (e) { /* optional */ } }
    }
    const shell = h("div", { class: "shell" },
      h("a", { class: "skip", href: "#content", onclick: (ev) => { ev.preventDefault(); $("#content").focus(); } }, "Skip to content"),
      h("header", { class: "topbar" },
        menuBtn,
        brandBlock(),
        h("span", { class: "pill", title: "Tenant", text: me.tenant_id }),
        h("span", { class: "spacer" }),
        helpLink(),
        h("span", { class: "live", id: "liveDot" }),
        h("div", { class: "who" },
          h("span", { class: "name", title: `${me.user_id} (${me.via})`, text: me.user_id }),
          ...roles.map((r) => h("span", { class: "pill accent", text: r }))),
        h("button", { class: "btn ghost sm", id: "signOut", onclick: () => signOut() }, "Sign out")),
      nav,
      h("main", { class: "content", id: "content", tabindex: "-1" }));
    $("#app").replaceChildren(shell);
    let saved = null; try { saved = localStorage.getItem("harnis.nav"); } catch (e) { /* optional */ }
    setMenu(narrow() ? false : saved !== "closed", false);
    // On a narrow screen the menu closes after you pick something, so the page is visible.
    nav.addEventListener("click", (ev) => { if (ev.target.closest("a") && narrow()) setMenu(false, false); });
    shell.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && narrow() && !shell.classList.contains("nav-closed")) { setMenu(false, false); menuBtn.focus(); } });
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
    for (const a of document.querySelectorAll(".nav a")) {
      const on = !!(view && a.dataset.view === view.id);
      a.classList.toggle("active", on);
      if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    }
    const content = $("#content");
    // After navigating, move keyboard and screen-reader focus to the page, not the link that was clicked.
    if (state.routed) content.focus({ preventScroll: true });
    state.routed = true;
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

  function expiresIn(v) {
    const s = Math.round((new Date(v).getTime() - Date.now()) / 1000);
    if (isNaN(s)) return "";
    if (s <= 0) return "expired";
    if (s < 3600) return `expires in ${Math.max(1, Math.round(s / 60))} min`;
    if (s < 86400) return `expires in ${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
    return `expires in ${Math.floor(s / 86400)} d`;
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
        a.agent ? h("span", { class: "pill", title: "Agent", text: a.agent }) : null,
        showSession ? h("a", { class: "small", href: `#/chat/${encodeURIComponent(a.session_id)}`, text: "open conversation" }) : null),
      a.context ? h("div", { class: "why small", title: "What the agent said before asking" }, h("strong", { text: "Agent said: " }), a.context) : null,
      h("div", { class: "body" }, actionDetail(a.action)),
      pending ? h("div", { class: "actions" },
        canApprove ? yes : null,
        (canApprove || own) ? no : null,
        !canApprove ? h("span", { class: "muted small", text: "Waiting for a reviewer to approve." }) : null,
        a.expires_at ? h("span", { class: "muted small expires", "data-expires": a.expires_at, title: fmtTime(a.expires_at), text: expiresIn(a.expires_at) }) : null,
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
    const traceBox = h("div", { class: "trace hidden", id: "traceBox" });
    const input = h("textarea", { id: "messageInput", rows: "1", placeholder: "Message the agents. Try: create calc.py with an add function" });
    const send = h("button", { class: "btn", id: "sendBtn" }, "Send");
    let busy = false;

    root.append(h("div", { class: "chat" },
      h("div", { class: "card sessions" },
        h("div", { class: "conv-head" }, h("h3", { text: "Conversations" }), h("span", { class: "spacer" }),
          h("button", { class: "btn sm", id: "newSession", onclick: () => newSession() }, "New")),
        list),
      h("div", { class: "card conv" }, head, messages, filesBox, traceBox,
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
      traceBox.classList.add("hidden");
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
        t.steps != null ? h("span", { class: "muted small", text: `${plural(t.steps, "step")} · ${plural(t.tool_calls || 0, "tool call")} · ${money(t.cost_usd)}${t.cache_hit ? " · cached" : ""}` }) : null,
        h("button", { class: "btn ghost sm", id: "traceBtn", onclick: toggleTrace }, "Trace"),
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
      if (v.escalation) nodes.push(handoverCard(v.escalation));
      messages.replaceChildren(...nodes);
      if (v.status === "awaiting_approval") showPendingApproval(v);
      messages.scrollTop = messages.scrollHeight;
    }

    // What a person taking over needs: what was asked, what the agent did, where it stopped, what to do next.
    function handoverCard(e) {
      const item = (label, value) => value ? h("div", { class: "row" }, h("strong", { text: label }), h("span", { text: value })) : null;
      const actions = (e.recent_actions || []).map((a) => `${a.ok ? "✓" : "✗"} ${a.tool}${a.target ? " " + a.target : ""}`);
      return h("div", { class: "card handover", id: "handover" },
        h("h3", { text: "Handover summary" }),
        item("What happened", e.what_happened),
        item("Asked", e.request),
        item("Files written", (e.files_written || []).join(", ") || "none"),
        item("Tests", e.tests),
        item("Spent this turn", money(e.spent_usd)),
        actions.length ? h("details", {}, h("summary", { text: "Recent actions" }),
          h("ul", {}, ...actions.map((t) => h("li", { class: "mono small", text: t })))) : null,
        h("strong", { text: "Suggested next steps" }),
        h("ul", {}, ...(e.next_steps || []).map((t) => h("li", { text: t }))));
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
        if (!traceBox.classList.contains("hidden")) loadTrace();
      } catch (e) {
        if (e.status === 404) { store.del("session"); current = ""; refresh(); return; }
        messages.replaceChildren(errorBox(e));
      }
    }

    // Timeline of one turn: each step is a bar placed by start time and sized by duration.
    async function loadTrace(turn) {
      try {
        const q = turn != null ? "?turn=" + turn : "";
        const tr = await api("GET", `/v1/sessions/${encodeURIComponent(current)}/trace${q}`);
        const es = tr.entries || [];
        const total = Math.max(0.001, ...es.map((e) => e.t + e.d));
        const label = (e) => e.kind === "model" ? `model ${e.model || ""} · ${e.in_tokens || 0}→${e.out_tokens || 0} tokens · ${money(e.cost)}`
          : e.kind === "approval" ? `approval wait · ${e.ok ? "approved" : "denied"} · ${e.tool}`
          : `${e.ok ? "✓" : "✗"} ${e.tool}${e.target ? " " + e.target : ""}`;
        const rows = es.map((e) => {
          const bar = h("span", { class: "bar " + e.kind + (e.ok === false ? " bad" : "") });
          bar.style.setProperty("left", (100 * e.t / total).toFixed(2) + "%");
          bar.style.setProperty("width", Math.max(0.8, 100 * e.d / total).toFixed(2) + "%");
          return h("div", { class: "trace-row" },
            h("span", { class: "trace-label mono small", text: label(e) }),
            h("span", { class: "track" }, bar),
            h("span", { class: "muted small", text: e.d.toFixed(2) + " s" }));
        });
        const picker = (tr.turns || []).length > 1
          ? h("span", {}, ...tr.turns.map((n) => h("button", { class: "btn ghost sm" + (n === tr.turn ? " active" : ""),
              onclick: () => loadTrace(n) }, "turn " + n))) : null;
        traceBox.replaceChildren(h("div", { class: "row" }, h("h3", { text: "Trace" }),
          h("span", { class: "muted small", text: es.length ? `${plural(es.length, "step")} · ${total.toFixed(1)} s` : "nothing recorded yet" }), picker),
          ...rows);
      } catch (e) { traceBox.replaceChildren(errorBox(e)); }
    }
    function toggleTrace() {
      if (!current) return;
      traceBox.classList.toggle("hidden");
      if (!traceBox.classList.contains("hidden")) loadTrace();
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
        let view = await api("POST", `/v1/sessions/${encodeURIComponent(current)}/turns`, { message: text });
        // With a turn queue the server may answer while a worker is still running the turn.
        for (let i = 0; view.status === "running" && i < 600; i++) {
          await new Promise((r) => setTimeout(r, 1500));
          view = await api("GET", `/v1/sessions/${encodeURIComponent(current)}`);
        }
        renderView(view);
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
    let rows = [];
    const tabs = h("div", { class: "row" }, ...["pending", "approved", "denied", "expired"].map((s) =>
      h("button", { class: "btn sm " + (s === status ? "" : "secondary"), "data-status": s, onclick: () => { status = s; load(); } }, s)));
    const fAgent = h("select", { id: "fAgent", "aria-label": "Filter by agent", onchange: () => draw() }, h("option", { value: "" }, "All agents"));
    const fTool = h("select", { id: "fTool", "aria-label": "Filter by tool", onchange: () => draw() }, h("option", { value: "" }, "All tools"));
    const fSort = h("select", { id: "fSort", "aria-label": "Sort", onchange: () => draw() },
      h("option", { value: "oldest" }, "Oldest first"), h("option", { value: "newest" }, "Newest first"),
      h("option", { value: "expiring" }, "Expiring soonest"));
    const notifyBtn = ("Notification" in window && Notification.permission === "default")
      ? h("button", { class: "btn sm secondary", id: "enableNotify", onclick: async () => {
          try { await Notification.requestPermission(); } catch { /* ignore */ }
          notifyBtn.classList.add("hidden");
        } }, "Alert me on this device")
      : null;
    const filters = h("div", { class: "row filters" }, fAgent, fTool, fSort, h("span", { class: "spacer" }), notifyBtn);
    root.append(pageHead("Approvals", "Every file change and command an agent proposes waits here for a reviewer. Approvals are bound to the exact action shown."), tabs, h("div", { class: "spacer" }), filters, body);
    body.classList.add("stack");
    function fillOptions(sel, values, all) {
      const cur = sel.value;
      sel.replaceChildren(h("option", { value: "" }, all), ...[...new Set(values.filter(Boolean))].sort().map((v) => h("option", { value: v }, v)));
      sel.value = values.includes(cur) ? cur : "";
    }
    function draw() {
      const shown = rows.filter((a) => (!fAgent.value || a.agent === fAgent.value) && (!fTool.value || a.action.tool === fTool.value));
      const t = (a) => new Date(a.requested_at).getTime();
      shown.sort(fSort.value === "newest" ? (a, b) => t(b) - t(a)
        : fSort.value === "expiring" ? (a, b) => new Date(a.expires_at) - new Date(b.expires_at) : (a, b) => t(a) - t(b));
      const none = rows.length && !shown.length ? "No approvals match these filters."
        : status === "pending" ? "Nothing is waiting for approval." : `No ${status} approvals.`;
      body.replaceChildren(...(shown.length ? shown.map((a) => approvalCard(a, { onDone: load })) : [h("div", { class: "card empty", text: none })]));
    }
    async function load() {
      for (const b of tabs.children) b.className = "btn sm " + (b.dataset.status === status ? "" : "secondary");
      try {
        rows = await api("GET", "/v1/approvals?status=" + status);
        fillOptions(fAgent, rows.map((a) => a.agent), "All agents");
        fillOptions(fTool, rows.map((a) => a.action.tool), "All tools");
        draw();
      } catch (e) { body.replaceChildren(errorBox(e)); }
    }
    listeners.add((e) => { if (e.type === "approval_required" && status === "pending") load(); });
    // Keep the "expires in" text current; stop once this page is gone.
    const tick = setInterval(() => {
      if (!root.isConnected) { clearInterval(tick); return; }
      for (const el of body.querySelectorAll(".expires")) {
        el.textContent = expiresIn(el.dataset.expires);
        el.classList.toggle("soon", new Date(el.dataset.expires) - Date.now() < 10 * 60 * 1000);
      }
    }, 15000);
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

    const days = h("select", { id: "reportDays", "aria-label": "Report period" },
      ...[[7, "7 days"], [30, "30 days"], [90, "90 days"]].map(([v, t]) => h("option", { value: String(v), text: t, selected: v === 30 })));
    const reports = h("div", { class: "stack", id: "reports" });
    if (has("reviewer")) {
      const bar = h("div", { class: "row" }, h("h2", { text: "Reports" }), h("span", { class: "spacer" }),
        h("label", { class: "muted small", for: "reportDays", text: "Period" }), days);
      bar.style.setProperty("margin-top", "16px");
      root.append(bar);
      root.append(reports);
      days.addEventListener("change", loadReports);
      loadReports();
    }
    async function loadReports() {
      reports.replaceChildren();
      const d = days.value;
      if (has("admin")) {
        const card = h("div", { class: "card", id: "spendCard" }, h("div", { class: "conv-head" }, h("h2", { text: "Spend by user and agent" })));
        reports.append(card);
        try {
          const r = await api("GET", `/v1/admin/spend?days=${d}`);
          card.append(h("p", { class: "muted small", text: "Agents are counted by the one a conversation ended on. Calls from conversations that have since been erased or expired are grouped together." }));
          card.append(table([
            { label: "User", render: (x) => h("span", { class: "mono", text: x.name }) },
            { label: "Conversations", num: true, render: (x) => num(x.sessions) },
            { label: "Calls", num: true, render: (x) => num(x.calls) },
            { label: "Tokens", num: true, render: (x) => num(Number(x.input_tokens) + Number(x.output_tokens)) },
            { label: "Cost", num: true, render: (x) => money(x.cost_usd) },
          ], r.by_user, "No spend in this period."));
          card.append(table([
            { label: "Agent", render: (x) => h("span", { class: "mono", text: x.name }) },
            { label: "Conversations", num: true, render: (x) => num(x.sessions) },
            { label: "Calls", num: true, render: (x) => num(x.calls) },
            { label: "Tokens", num: true, render: (x) => num(Number(x.input_tokens) + Number(x.output_tokens)) },
            { label: "Cost", num: true, render: (x) => money(x.cost_usd) },
          ], r.by_agent, ""));
          if (r.by_user.length) card.append(h("div", { class: "conv-head" }, h("span", { class: "spacer" }), h("strong", { text: "Total " + money(r.total_usd) })));
        } catch (e) { card.append(errorBox(e)); }
      }
      const ac = h("div", { class: "card", id: "approvalStats" }, h("div", { class: "conv-head" }, h("h2", { text: "Approvals" })));
      reports.append(ac);
      try {
        const a = await api("GET", `/v1/approval-stats?days=${d}`);
        const dur = (sec) => sec == null ? "n/a" : sec < 90 ? Math.round(sec) + " s" : sec < 5400 ? Math.round(sec / 60) + " min" : (sec / 3600).toFixed(1) + " h";
        ac.append(table([{ label: "Measure", key: "m" }, { label: "Value", key: "v" }], [
          { m: "Requests", v: String(a.total) },
          { m: "Approved / denied", v: `${a.approved} / ${a.denied}` },
          { m: "Approval rate (of decided)", v: a.approval_rate_pct == null ? "n/a" : a.approval_rate_pct + "%" },
          { m: "Expired without a decision", v: a.total ? `${a.expired} (${a.expired_pct}%)` : "0" },
          { m: "Still waiting", v: String(a.pending) },
          { m: "Median time to decide", v: dur(a.median_decision_s) },
          { m: "90th percentile", v: dur(a.p90_decision_s) },
        ], ""));
        if (a.by_tool.length) ac.append(table([
          { label: "Tool", render: (x) => h("span", { class: "mono", text: x.tool }) },
          { label: "Approved", num: true, key: "approved" }, { label: "Denied", num: true, key: "denied" },
          { label: "Expired", num: true, key: "expired" }, { label: "Waiting", num: true, key: "pending" },
        ], a.by_tool, ""));
      } catch (e) { ac.append(errorBox(e)); }
    }

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
      const sc = h("div", { class: "card", id: "scorecard" }, h("div", { class: "conv-head" }, h("h2", { text: "Health scorecard" }),
        h("span", { class: "muted small", text: "last 24 hours" })));
      sc.style.setProperty("margin-top", "16px");
      root.append(sc);
      try {
        const d = await api("GET", "/v1/scorecard");
        if (d.trip.writes_frozen || d.trip.paused) {
          sc.append(h("div", { class: "notice error", id: "tripNotice", text: `Safety trip wire: ${d.trip.paused ? "tenant paused, " : ""}writes are frozen (${d.trip.reason || "unknown"}). An administrator must clear it.` }));
        }
        const cap = (used, max) => max ? `${money(used)} of ${money(max)}` : money(used) + " (no cap)";
        const ev = d.safety_events || {};
        const evText = Object.keys(ev).length ? Object.entries(ev).map(([k, v]) => `${k.replace(/_/g, " ")} ${v}`).join(", ") : "none";
        sc.append(table([{ label: "Measure", key: "m" }, { label: "Value", key: "v" }], [
          { m: "Turns", v: String(d.turns) },
          { m: "Success / failed or escalated", v: d.turns ? `${d.success_pct}% / ${d.failure_pct}%` : "no turns yet" },
          { m: "Pending approvals", v: String(d.pending_approvals) },
          { m: "Spend today", v: cap(d.spend.today_usd, d.spend.max_per_day) },
          { m: "Spend this month", v: cap(d.spend.month_usd, d.spend.max_per_month) },
          { m: "Time limit per turn", v: d.controls.max_turn_seconds ? d.controls.max_turn_seconds + " s" : "platform default" },
          { m: "Tests required before a coding turn completes", v: d.controls.require_tests ? "yes" : "no" },
          { m: "Safety events", v: evText },
        ], ""));
      } catch (e) { sc.append(errorBox(e)); }
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
  // ---------------------------------------------------------------------------
  // Start: pick who to talk to (the landing page for people with only the user role)
  // ---------------------------------------------------------------------------
  async function viewStart(root) {
    root.append(pageHead("Start a conversation", "Choose who you want to work with, or just ask and the right assistant is picked for you. Anything that changes files or runs commands waits for a reviewer to approve it first."));
    const grid = h("div", { class: "grid", id: "catalogue" });
    root.append(grid);
    const begin = async (agent, btn) => {
      btn.disabled = true;
      try {
        const { session_id } = await api("POST", "/v1/sessions", agent ? { agent } : {});
        store.set("session", session_id);
        location.hash = "#/chat/" + encodeURIComponent(session_id);
      } catch (e) { toast(e.message, "error"); btn.disabled = false; }
    };
    const card = (key, title, text, extra, recommended) => {
      const btn = h("button", { class: "btn", "data-start": key || "auto", onclick: (ev) => begin(key, ev.currentTarget) }, "Start conversation");
      return h("div", { class: "card pad stack", "data-agent": key || "auto" },
        h("div", { class: "row" }, h("h2", { text: title }), recommended ? h("span", { class: "pill accent", text: "recommended" }) : null),
        h("p", { class: "muted", text }), extra, h("div", { class: "row" }, btn));
    };
    grid.append(card(null, "Not sure? Just ask", "Describe what you need. The right assistant is chosen from your first message.", null, false));
    try {
      const agents = await api("GET", "/v1/agents");
      for (const a of agents) {
        const asks = (a.tools || []).filter((t) => t.risk === "high").map((t) => t.name);
        const note = asks.length
          ? h("p", { class: "small", title: asks.join(", ") }, h("strong", { text: "Asks a reviewer first: " }), asks.join(", "))
          : h("p", { class: "small muted", text: "Does not change anything." });
        grid.append(card(a.name, a.title || a.name, a.summary || a.description, note, a.default));
      }
    } catch (e) { grid.append(errorBox(e)); }
  }

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
  // Scheduled tasks
  // ---------------------------------------------------------------------------
  const DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  function describeSchedule(sc, tz) {
    if (sc.kind === "every") return sc.minutes % 60 === 0 ? `every ${plural(sc.minutes / 60, "hour")}` : `every ${plural(sc.minutes, "minute")}`;
    if (sc.kind === "daily") return `daily at ${sc.at} (${tz})`;
    return `${sc.days.map((d) => DAY_NAMES[d]).join(", ")} at ${sc.at} (${tz})`;
  }

  async function viewSchedules(root) {
    root.append(pageHead("Schedules", "Send a message to an agent on a schedule. Each run is a normal conversation started as you, so changes and commands still wait in Approvals; a run that reaches an approval stops there."));
    const notice = h("div", {});
    const name = h("input", { type: "text", id: "schName", maxlength: "120", placeholder: "e.g. Morning dependency check" });
    const message = h("textarea", { id: "schMessage", rows: "3", maxlength: "50000", placeholder: "What should the agent do each time?" });
    const agent = h("select", { id: "schAgent" }, h("option", { value: "", text: "Let Harnis choose" }));
    const kind = h("select", { id: "schKind" },
      h("option", { value: "daily", text: "Every day" }), h("option", { value: "weekly", text: "On chosen days" }),
      h("option", { value: "every", text: "Every N minutes" }));
    const at = h("input", { type: "time", id: "schAt", value: "09:00" });
    const minutes = h("input", { type: "number", id: "schMinutes", min: "1", value: "60" });
    const dayBoxes = DAY_NAMES.map((d, i) => h("input", { type: "checkbox", value: String(i), checked: i < 5 }));
    const days = h("div", { class: "row" }, ...dayBoxes.map((b, i) => h("label", { class: "check" }, b, DAY_NAMES[i])));
    const tz = h("input", { type: "text", id: "schTz", value: (Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC") });
    const timeField = h("label", { class: "field" }, "Time", at);
    const minField = h("label", { class: "field" }, "Minutes between runs", minutes);
    const listBox = h("div", { class: "card" });
    const sync = () => {
      timeField.classList.toggle("hidden", kind.value === "every");
      minField.classList.toggle("hidden", kind.value !== "every");
      days.classList.toggle("hidden", kind.value !== "weekly");
    };
    kind.addEventListener("change", sync);
    const form = h("form", { class: "card pad stack", id: "schForm", onsubmit: async (ev) => {
      ev.preventDefault();
      const schedule = kind.value === "every" ? { kind: "every", minutes: Number(minutes.value) }
        : kind.value === "daily" ? { kind: "daily", at: at.value }
        : { kind: "weekly", days: dayBoxes.filter((b) => b.checked).map((b) => Number(b.value)), at: at.value };
      if (!name.value.trim() || !message.value.trim()) { toast("Give the task a name and a message.", "error"); return; }
      try {
        await api("POST", "/v1/schedules", { name: name.value.trim(), message: message.value.trim(),
          agent: agent.value || null, schedule, timezone: tz.value.trim() || "UTC" });
        name.value = ""; message.value = "";
        toast("Scheduled."); load();
      } catch (e) { toast(e.message, "error"); }
    } },
      h("h2", { text: "New scheduled task" }),
      h("label", { class: "field" }, "Name", name),
      h("label", { class: "field" }, "Message", message),
      h("div", { class: "row" }, h("label", { class: "field" }, "Agent", agent),
        h("label", { class: "field" }, "How often", kind), timeField, minField,
        h("label", { class: "field" }, "Time zone", tz)),
      days,
      h("div", { class: "row" }, h("button", { class: "btn", type: "submit", id: "schCreate" }, "Schedule it")));
    listBox.style.setProperty("margin-top", "16px");
    root.append(notice, form, listBox);
    sync();
    api("GET", "/v1/agents").then((as) => as.forEach((a) => agent.append(h("option", { value: a.name, text: a.name })))).catch(() => {});

    async function act(fn, ok) {
      try { await fn(); if (ok) toast(ok); } catch (e) { toast(e.message, "error"); }
      load();
    }
    async function load() {
      try {
        const r = await api("GET", "/v1/schedules");
        notice.replaceChildren(r.scheduler_enabled ? "" : h("div", { class: "notice warn", id: "schOff",
          text: "The scheduler is turned off on this server, so tasks will not run on their own (SCHEDULER_ENABLED=true turns it on). You can still use Run now." }));
        listBox.replaceChildren(table([
          { label: "Name", key: "name" },
          { label: "When", render: (t) => describeSchedule(t.schedule, t.timezone) },
          { label: "Next run", render: (t) => t.enabled && t.next_run_at ? fmtTime(t.next_run_at) : "paused" },
          { label: "Last run", render: (t) => t.last_run_at ? h("span", {}, statusPill(t.last_status || "started"), " ", ago(t.last_run_at),
            t.last_session_id ? h("span", {}, " · ", h("a", { href: "#/chat/" + encodeURIComponent(t.last_session_id), text: "open" })) : "") : "never" },
          { label: "", render: (t) => h("span", { class: "row" },
            h("button", { class: "btn sm secondary", "data-run": t.task_id, onclick: () => act(() => api("POST", `/v1/schedules/${t.task_id}/run`), "Started.") }, "Run now"),
            h("button", { class: "btn sm secondary", onclick: () => act(() => api("PATCH", `/v1/schedules/${t.task_id}`, { enabled: !t.enabled })) }, t.enabled ? "Pause" : "Resume"),
            deleteButton(t)) },
        ], r.tasks, "Nothing scheduled yet."));
      } catch (e) { listBox.replaceChildren(errorBox(e)); }
    }
    function deleteButton(t) {
      const b = h("button", { class: "btn sm secondary", "data-delete": t.task_id }, "Delete");
      b.addEventListener("click", () => {
        if (b.dataset.confirm !== "1") { b.dataset.confirm = "1"; b.textContent = "Confirm delete"; b.className = "btn sm danger"; return; }
        act(() => api("DELETE", "/v1/schedules/" + t.task_id), "Deleted.");
      });
      return b;
    }
    load();
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
    const who = h("input", { type: "text", id: "auditUser", placeholder: "user, as shown under Actor" });
    const from = h("input", { type: "date", id: "auditFrom", "aria-label": "From date" });
    const to = h("input", { type: "date", id: "auditTo", "aria-label": "To date (inclusive)" });
    const tbody = h("tbody", {});
    const more = h("button", { class: "btn secondary sm hidden", onclick: () => load(false) }, "Load more");
    let after = 0;
    root.append(pageHead("Audit log", "Security-relevant events in this tenant, oldest first. Append-only.",
      h("button", { class: "btn secondary sm", id: "downloadAudit", onclick: download }, "Download NDJSON")));
    root.append(h("form", { class: "row", onsubmit: (ev) => { ev.preventDefault(); load(true); } },
      h("div", { class: "spacer" }, filter), h("div", { class: "spacer" }, who),
      h("label", { class: "muted small", text: "From" }), from, h("label", { class: "muted small", text: "To" }), to,
      h("button", { class: "btn sm", type: "submit" }, "Filter")));
    const card = h("div", { class: "card table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ...["#", "Time", "Actor", "Event", "Session", "Detail"].map((t) => h("th", { text: t })))), tbody));
    card.style.setProperty("margin-top", "12px");
    root.append(card, h("div", { class: "row" }, more));

    const q = () => {
      let out = "";
      if (filter.value.trim()) out += "&event_type=" + encodeURIComponent(filter.value.trim());
      if (who.value.trim()) out += "&actor=" + encodeURIComponent(who.value.trim());
      if (from.value) out += "&since=" + encodeURIComponent(new Date(from.value + "T00:00:00").toISOString());
      if (to.value) { const d = new Date(to.value + "T00:00:00"); d.setDate(d.getDate() + 1); out += "&until=" + encodeURIComponent(d.toISOString()); }
      return out;
    };
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
      const day = h("input", { type: "number", id: "tenantDay", min: "0", step: "0.01", placeholder: "no cap" });
      const month = h("input", { type: "number", id: "tenantMonth", min: "0", step: "0.01", placeholder: "no cap" });
      const secs = h("input", { type: "number", id: "tenantSecs", min: "0", step: "1", placeholder: "platform default" });
      const reqTests = h("input", { type: "checkbox", id: "tenantReqTests", checked: !!(t && t.require_tests) });
      const active = h("input", { type: "checkbox", id: "tenantActive", checked: t ? t.active : true });
      if (t) { id.value = t.tenant_id; nm.value = t.name || ""; prov.value = (t.allowed_providers || []).join(", "); cap.value = t.max_cost_usd_per_turn ?? ""; day.value = t.max_cost_usd_per_day ?? ""; month.value = t.max_cost_usd_per_month ?? ""; secs.value = t.max_turn_seconds ?? ""; }
      const lim = (el, cur) => el.value === "" ? (t && cur != null ? 0 : null) : Number(el.value);
      const form = h("form", { class: "card pad stack", onsubmit: async (ev) => {
        ev.preventDefault();
        const tid = id.value.trim();
        if (!tid) { toast("Enter a tenant id.", "error"); return; }
        const body = { name: nm.value.trim() || null, active: active.checked,
          allowed_providers: prov.value.trim() ? prov.value.split(",").map((s) => s.trim()).filter(Boolean) : (t ? null : ["*"]),
          max_cost_usd_per_turn: cap.value === "" ? (t && t.max_cost_usd_per_turn != null ? 0 : null) : Number(cap.value),
          max_cost_usd_per_day: lim(day, t && t.max_cost_usd_per_day), max_cost_usd_per_month: lim(month, t && t.max_cost_usd_per_month),
          max_turn_seconds: lim(secs, t && t.max_turn_seconds), require_tests: reqTests.checked };
        try {
          await api("PUT", "/v1/admin/tenants/" + encodeURIComponent(tid), body);
          toast(`Tenant ${tid} saved.`); formBox.replaceChildren(); load();
        } catch (e) { toast(e.message, "error"); }
      } },
        h("h2", { text: t ? `Edit ${t.tenant_id}` : "New tenant" }),
        h("div", { class: "row" }, h("label", { class: "field spacer" }, "Tenant id", id), h("label", { class: "field spacer" }, "Name", nm)),
        h("div", { class: "row" }, h("label", { class: "field spacer" }, "Allowed model providers (comma-separated)", prov),
          h("label", { class: "field" }, "Max cost per turn (USD)", cap)),
        h("div", { class: "row" }, h("label", { class: "field spacer" }, "Daily budget (USD)", day),
          h("label", { class: "field spacer" }, "Monthly budget (USD)", month),
          h("label", { class: "field spacer" }, "Time limit per turn (seconds)", secs)),
        h("label", { class: "check" }, reqTests, "Require passing tests before a coding turn completes"),
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
          { label: "Daily / monthly", num: true, render: (r) => (r.max_cost_usd_per_day ? "$" + r.max_cost_usd_per_day : "-") + " / " + (r.max_cost_usd_per_month ? "$" + r.max_cost_usd_per_month : "-") },
          { label: "Status", render: (r) => statusPill(r.writes_frozen ? "tripped" : (r.active ? "active" : "disabled")) },
          { label: "Created", render: (r) => fmtTime(r.created_at) },
          { label: "", render: (r) => h("div", { class: "row" },
              h("button", { class: "btn sm secondary", "data-edit": r.tenant_id, onclick: () => edit(r) }, "Edit"),
              (r.writes_frozen || !r.active) && r.tripped_reason ? h("button", { class: "btn sm", "data-clear": r.tenant_id, title: r.tripped_reason, onclick: async () => {
                try { await api("POST", `/v1/admin/tenants/${encodeURIComponent(r.tenant_id)}/clear-trip`); toast("Trip wire cleared."); load(); } catch (e) { toast(e.message, "error"); } } }, "Clear trip") : null,
              r.active ? null : h("button", { class: "btn sm danger", "data-delete": r.tenant_id, onclick: () => remove(r) }, "Delete...")) },
        ], rows, "No tenants."));
      } catch (e) { listBox.replaceChildren(errorBox(e)); }
    }
    load();
  }
  STATUS_KIND.active = "ok"; STATUS_KIND.tripped = "danger"; STATUS_KIND.disabled = "danger"; STATUS_KIND.revoked = "danger";
  STATUS_KIND.confirmed = "ok"; STATUS_KIND.unconfirmed = "warn";

  // ---------------------------------------------------------------------------
  // Start
  // ---------------------------------------------------------------------------
  async function boot() {
    try {
      const r = await fetch("/v1/auth/config");
      state.config = await r.json();
      applyBrand();
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

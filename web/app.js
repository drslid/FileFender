(() => {
  "use strict";

  const I18N = window.FILEFENDER_I18N;
  const VERSION = document.querySelector('meta[name="filefender-version"]').content;
  const ASSETS = document.querySelector('meta[name="filefender-assets"]').content;
  const STORE = { lang: "filefender.lang", theme: "filefender.theme" };
  const state = {
    user: null,
    lang: "en",
    status: null,
    timer: null,
    page: null,
    report: null,
    busy: false,
    keys: null,
    newKey: null,
    editingKey: null,
    settings: null,
    draft: null,
    newSecrets: null,
    lists: null,
    audit: null,
    users: null,
    editingUser: null,
  };

  // Each role can do everything the previous one can; the server enforces it.
  const ROLES = ["viewer", "operator", "admin"];
  const can = (role) => ROLES.indexOf(state.user?.role) >= ROLES.indexOf(role);
  const PAGES = { dashboard: "viewer", scan: "operator", lists: "operator", api: "admin", settings: "admin", activity: "viewer", account: "viewer" };

  // ---------- small helpers

  const $ = (selector, root = document) => root.querySelector(selector);

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [name, value] of Object.entries(attrs || {})) {
      if (value === undefined || value === null || value === false) continue;
      if (name === "class") el.className = value;
      else if (name.startsWith("on")) el.addEventListener(name.slice(2), value);
      else el.setAttribute(name, value === true ? "" : value);
    }
    for (const child of children.flat(Infinity)) {
      if (child === undefined || child === null || child === false) continue;
      el.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return el;
  }

  const SVG = "http://www.w3.org/2000/svg";
  function icon(...shapes) {
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    for (const [tag, attrs] of shapes) {
      const node = document.createElementNS(SVG, tag);
      for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
      svg.append(node);
    }
    return svg;
  }
  const shield = ["path", { d: "M12 3 19 6v5.5c0 4.6-3 8.1-7 9.5-4-1.4-7-4.9-7-9.5V6Z" }];
  const ICONS = {
    check: () => icon(shield, ["path", { d: "m9 12 2.2 2.2L15.5 10" }]),
    alert: () => icon(shield, ["path", { d: "M12 8v4.5" }], ["circle", { cx: "12", cy: "15.8", r: "0.6" }]),
    cross: () => icon(shield, ["path", { d: "m9.5 9.5 5 5m0-5-5 5" }]),
    database: () => icon(["ellipse", { cx: "12", cy: "6", rx: "7", ry: "3" }], ["path", { d: "M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3" }]),
    rules: () => icon(["path", { d: "M8 4H6.5A1.5 1.5 0 0 0 5 5.5v4L3.5 12 5 14.5v4A1.5 1.5 0 0 0 6.5 20H8M16 4h1.5A1.5 1.5 0 0 1 19 5.5v4l1.5 2.5-1.5 2.5v4a1.5 1.5 0 0 1-1.5 1.5H16" }], ["path", { d: "M9.5 12h5" }]),
    hash: () => icon(["path", { d: "M9 4 7.5 20M16.5 4 15 20M4.5 9h15M4 15h15" }]),
    upload: () => icon(["path", { d: "M12 15V4m0 0L8 8m4-4 4 4" }], ["path", { d: "M4 14v3.5A2.5 2.5 0 0 0 6.5 20h11a2.5 2.5 0 0 0 2.5-2.5V14" }]),
    copy: () => icon(["rect", { x: "8", y: "8", width: "12", height: "12", rx: "2" }], ["path", { d: "M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" }]),
    sun: () => icon(["circle", { cx: "12", cy: "12", r: "4" }], ["path", { d: "M12 2.5v2M12 19.5v2M4.6 4.6 6 6M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4 6 18M18 6l1.4-1.4" }]),
    moon: () => icon(["path", { d: "M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5Z" }]),
    logout: () => icon(["path", { d: "M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3M10 16l-4-4 4-4M6 12h10" }]),
  };

  function t(key, vars) {
    const table = I18N.strings[state.lang] || I18N.strings.en;
    let text = table[key] ?? I18N.strings.en[key] ?? key;
    if (vars) text = text.replace(/\{(\w+)\}/g, (match, name) => (name in vars ? vars[name] : match));
    return text;
  }

  const fmt = {
    number: (n) => new Intl.NumberFormat(state.lang).format(n ?? 0),
    bytes(n) {
      const units = ["byte", "kilobyte", "megabyte", "gigabyte"];
      let value = n ?? 0;
      let i = 0;
      while (value >= 1024 && i < units.length - 1) {
        value /= 1024;
        i += 1;
      }
      return new Intl.NumberFormat(state.lang, {
        style: "unit",
        unit: units[i],
        // "short" renders "264 byte" in English; the long form is properly pluralized.
        unitDisplay: i === 0 ? "long" : "short",
        maximumFractionDigits: i > 0 && value < 10 ? 1 : 0,
      }).format(value);
    },
    ms(n) {
      const seconds = n >= 1000;
      return new Intl.NumberFormat(state.lang, {
        style: "unit",
        unit: seconds ? "second" : "millisecond",
        unitDisplay: "short",
        maximumFractionDigits: seconds ? 1 : 0,
      }).format(seconds ? n / 1000 : n);
    },
    relative(iso) {
      if (!iso) return t("time.never");
      const diff = (new Date(iso).getTime() - Date.now()) / 1000;
      const rtf = new Intl.RelativeTimeFormat(state.lang, { numeric: "auto" });
      const abs = Math.abs(diff);
      if (abs < 60) return rtf.format(Math.round(diff), "second");
      if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
      if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
      return rtf.format(Math.round(diff / 86400), "day");
    },
    uptime(total) {
      const parts = [
        ["day", Math.floor(total / 86400)],
        ["hour", Math.floor((total % 86400) / 3600)],
        ["minute", Math.floor((total % 3600) / 60)],
      ].filter(([, v]) => v > 0);
      if (!parts.length) parts.push(["minute", 0]);
      return parts
        .slice(0, 2)
        .map(([unit, v]) => new Intl.NumberFormat(state.lang, { style: "unit", unit, unitDisplay: "short" }).format(v))
        .join(" ");
    },
    time: (iso) => new Intl.DateTimeFormat(state.lang, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(iso)),
    date: (iso) => new Intl.DateTimeFormat(state.lang, { dateStyle: "medium", timeStyle: "short" }).format(new Date(iso)),
    day: (iso) => new Intl.DateTimeFormat(state.lang, { dateStyle: "medium", timeZone: "UTC" }).format(new Date(iso)),
  };

  // The EICAR test string, stored shifted so that this file never matches antivirus signatures.
  const EICAR_SHIFTED = "Y6P\"Q&ABQ\\5]Q[Y65)Q_*8DD*8~%FJDBS.TUBOEBSE.BOUJWJSVT.UFTU.GJMF\"%I,I+";
  const eicar = () => Array.from(EICAR_SHIFTED, (c) => String.fromCharCode(c.charCodeAt(0) - 1)).join("");

  // ---------- preferences

  function setLanguage(code, rerender = true) {
    const known = I18N.languages.find((l) => l.code === code) || I18N.languages[0];
    state.lang = known.code;
    localStorage.setItem(STORE.lang, known.code);
    document.documentElement.lang = known.code;
    document.documentElement.dir = known.rtl ? "rtl" : "ltr";
    for (const el of document.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
    for (const el of document.querySelectorAll("[data-i18n-title]")) {
      el.title = t(el.dataset.i18nTitle);
      el.setAttribute("aria-label", t(el.dataset.i18nTitle));
    }
    $("#lang").value = known.code;
    renderFooter();
    renderHealth();
    if (rerender) route();
  }

  function detectLanguage() {
    const saved = localStorage.getItem(STORE.lang);
    if (saved) return saved;
    for (const wanted of navigator.languages || [navigator.language]) {
      const base = String(wanted).toLowerCase().split("-")[0];
      if (I18N.languages.some((l) => l.code === base)) return base;
    }
    return "en";
  }

  function applyTheme(theme) {
    const dark = theme === "dark" || (theme !== "light" && matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    $("#theme").replaceChildren(dark ? ICONS.sun() : ICONS.moon());
  }

  // ---------- server calls

  // Every call carries the CSRF header; the session itself is an HttpOnly cookie.
  async function call(method, path, body) {
    const headers = { "X-FileFender-CSRF": "1" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      credentials: "same-origin",
    });
    let data = null;
    try {
      data = await response.json();
    } catch {
      /* empty body */
    }
    return { ok: response.ok, status: response.status, data, code: data?.error?.code, message: data?.error?.message };
  }

  // Calls made while signed in: an expired session brings back the sign-in form.
  async function api(method, path, body) {
    const result = await call(method, path, body);
    if (result.status === 401) {
      sessionEnded();
      throw new Error("unauthorized");
    }
    return result;
  }

  async function refreshStatus() {
    try {
      const result = await api("GET", "/v1/status");
      if (!result.ok) return;
      const first = !state.status;
      state.status = result.data;
      renderHealth();
      renderFooter();
      if (state.page === "dashboard") renderDashboard();
      if (state.page === "scan" && !state.busy && !$(".dropzone small")) renderScan();
      // The settings page shows database and feed details from the status once.
      if (state.page === "settings" && first && state.settings) renderSettings();
    } catch (err) {
      if (err.message !== "unauthorized") setHealth("bad", t("signin.offline"));
    }
  }

  function startPolling() {
    stopPolling();
    refreshStatus();
    state.timer = setInterval(() => {
      if (document.visibilityState === "visible") refreshStatus();
    }, 5000);
  }

  function stopPolling() {
    clearInterval(state.timer);
    state.timer = null;
  }

  // ---------- chrome

  function setHealth(kind, text) {
    const pill = $("#health");
    pill.hidden = false;
    pill.className = `pill ${kind}`;
    pill.textContent = text;
  }

  function renderHealth() {
    const s = state.status;
    if (!s) return;
    const broken = [s.engines.clamav.status, s.engines.yara.status].includes("error");
    if (s.ready) setHealth("ok", t("status.ready"));
    else setHealth(broken ? "bad" : "warn", t(broken ? "status.error" : "status.starting"));
  }

  function renderFooter() {
    $("#footer").replaceChildren(
      `FileFender ${VERSION} · ${t("footer.text")} · `,
      h("a", { href: "https://github.com/drslid/FileFender", rel: "noopener noreferrer", target: "_blank" }, "GitHub"),
    );
  }

  function resetSession() {
    stopPolling();
    state.user = null;
    state.status = null;
    state.report = null;
    state.keys = null;
    state.newKey = null;
    state.editingKey = null;
    state.settings = null;
    state.draft = null;
    state.newSecrets = null;
    state.lists = null;
    state.audit = null;
    state.users = null;
    state.editingUser = null;
  }

  function sessionEnded() {
    resetSession();
    renderLogin(t("login.expired"));
  }

  async function signOut() {
    try {
      await call("DELETE", "/v1/session");
    } catch {
      /* the cookie expires anyway */
    }
    resetSession();
    renderLogin();
  }

  // ---------- first visit and sign in

  async function start() {
    try {
      const setup = await call("GET", "/v1/setup");
      if (setup.data?.required) return renderSetup(setup.data);
      const session = await call("GET", "/v1/session");
      if (session.ok) {
        state.user = session.data;
        return route();
      }
      renderLogin();
    } catch {
      renderLogin(t("signin.offline"));
    }
  }

  function signedIn(user) {
    state.user = user;
    if (location.hash === "#/dashboard") route();
    else location.hash = "#/dashboard";
  }

  const input = (attrs) => h("input", { spellcheck: "false", autocapitalize: "off", ...attrs });
  const logo = () => h("img", { src: `/assets/logo.svg?v=${ASSETS}`, alt: "" });
  const longEnough = (password) => [...password].length >= 12;

  function field(label, control, hint) {
    return h("label", { class: "field" }, label, control, hint ? h("small", { class: "muted" }, hint) : null);
  }

  function authPage(card) {
    stopPolling();
    $("#tabs").hidden = true;
    $("#signout").hidden = true;
    $("#health").hidden = true;
    $("#app").replaceChildren(h("section", { class: "signin-wrap" }, card));
  }

  function renderSetup(setup) {
    if (!setup.open) {
      authPage(
        h(
          "section",
          { class: "card signin" },
          logo(),
          h("h1", null, t("setup.closedTitle")),
          h("p", null, t("setup.closedText")),
          h("code", { class: "command" }, "docker restart filefender"),
        ),
      );
      return;
    }
    const username = input({ autocomplete: "username", required: true, maxlength: "64", value: "admin" });
    const password = input({ type: "password", autocomplete: "new-password", required: true });
    const confirm = input({ type: "password", autocomplete: "new-password", required: true });
    const error = h("p", { class: "form-error", role: "alert" });
    const submit = h("button", { class: "btn", type: "submit" }, t("setup.submit"));
    const minutes = setup.remaining_seconds ? Math.max(1, Math.ceil(setup.remaining_seconds / 60)) : null;
    const form = h(
      "form",
      {
        class: "card signin",
        onsubmit: async (event) => {
          event.preventDefault();
          error.textContent = "";
          if (!longEnough(password.value)) {
            error.textContent = t("password.hint");
            return;
          }
          if (password.value !== confirm.value) {
            error.textContent = t("password.mismatch");
            return;
          }
          submit.disabled = true;
          try {
            const result = await call("POST", "/v1/setup", { username: username.value, password: password.value });
            if (result.ok) return signedIn(result.data);
            if (result.code === "already_set_up") return renderLogin(t("setup.taken"));
            if (result.code === "setup_closed") return renderSetup({ open: false });
            error.textContent = result.message || t("signin.offline");
          } catch {
            error.textContent = t("signin.offline");
          }
          submit.disabled = false;
        },
      },
      logo(),
      h("h1", null, t("setup.title")),
      h("p", null, t("setup.text")),
      field(t("field.username"), username),
      field(t("field.password"), password, t("password.hint")),
      field(t("field.confirm"), confirm),
      error,
      submit,
      minutes ? h("p", { class: "help muted" }, t("setup.window", { minutes })) : null,
    );
    authPage(form);
    password.focus();
  }

  function renderLogin(message) {
    const username = input({ autocomplete: "username", required: true });
    const password = input({ type: "password", autocomplete: "current-password", required: true });
    const code = input({ autocomplete: "one-time-code", maxlength: "16", dir: "ltr" });
    const codeField = field(t("field.code"), code, t("login.codeHelp"));
    codeField.hidden = true;
    const error = h("p", { class: "form-error", role: "alert" }, message || "");
    const submit = h("button", { class: "btn", type: "submit" }, t("signin.submit"));
    const form = h(
      "form",
      {
        class: "card signin",
        onsubmit: async (event) => {
          event.preventDefault();
          error.textContent = "";
          submit.disabled = true;
          try {
            const result = await call("POST", "/v1/session", {
              username: username.value,
              password: password.value,
              code: codeField.hidden ? undefined : code.value,
            });
            if (result.ok) return signedIn(result.data);
            if (result.code === "setup_required") return start();
            if (result.code === "totp_required") {
              codeField.hidden = false;
              code.focus();
            } else {
              const reason = { invalid_code: "login.badCode", invalid_credentials: "login.invalid", too_many_failures: "login.throttled" }[result.code];
              error.textContent = t(reason || "signin.offline");
            }
          } catch {
            error.textContent = t("signin.offline");
          }
          submit.disabled = false;
        },
      },
      logo(),
      h("h1", null, t("login.title")),
      h("p", null, t("login.text")),
      field(t("field.username"), username),
      field(t("field.password"), password),
      codeField,
      error,
      submit,
    );
    authPage(form);
    username.focus();
  }

  // ---------- dashboard

  function badge(status) {
    return h("span", { class: `badge s-${status}` }, t(`status.${status}`));
  }

  function engineCard(iconFn, title, description, status, rows, note) {
    return h(
      "article",
      { class: "card engine" },
      h("header", { class: "engine-head" }, h("span", { class: "engine-icon" }, iconFn()), h("div", null, h("h3", null, title), h("p", null, description)), status ? badge(status) : null),
      h("dl", { class: "rows" }, rows.map(([label, value]) => [h("dt", null, label), h("dd", null, value)])),
      note,
    );
  }

  function protectionCard(s) {
    const p = s.protection || {};
    const feeds = (s.engines.clamav.feeds || []).filter((f) => f.enabled).length;
    const on = (count) => (count ? t("protection.on", { count: fmt.number(count) }) : t("protection.off"));
    let policy = t("protection.off");
    if (p.blocked_types?.length) policy = p.blocked_types.map((c) => t(`policy.${c}`)).join(", ");
    else if (p.disguised_files) policy = t("protection.disguisedOnly");
    const facts = [
      [t("protection.feeds"), on(feeds)],
      [t("protection.policy"), policy],
      [t("protection.lists"), t("protection.listsCount", { allow: fmt.number(p.allowlist), block: fmt.number(p.blocklist) })],
      [t("protection.alerts"), on(p.webhooks)],
      [t("protection.access"), t(p.dashboard_restricted ? "protection.restricted" : "protection.open")],
    ];
    return h(
      "section",
      { class: "card protection" },
      h(
        "header",
        { class: "engine-head" },
        h("span", { class: "engine-icon" }, ICONS.check()),
        h("div", null, h("h3", null, t("protection.title")), can("admin") ? h("p", null, h("a", { href: "#/settings" }, t("protection.manage"))) : null),
      ),
      h("dl", { class: "facts-row" }, facts.map(([label, value]) => h("div", null, h("dt", null, label), h("dd", null, value)))),
    );
  }

  function renderDashboard() {
    const s = state.status;
    if (!s) return;
    const { clamav, yara, malwarebazaar } = s.engines;
    const daily = (clamav.databases || []).find((d) => d.name === "daily");
    const broken = [clamav.status, yara.status].includes("error");
    const heroClass = s.ready ? "" : broken ? "problem" : "starting";
    const cert = s.tls.mode === "off" ? t("cert.none") : `${t(`cert.${s.tls.certificate}`)} · ${s.tls.domain}`;

    const hero = h(
      "section",
      { class: `card hero ${heroClass}` },
      h("span", { class: "hero-icon" }, s.ready ? ICONS.check() : broken ? ICONS.cross() : ICONS.alert()),
      h("div", { class: "hero-text" }, h("h1", null, t(s.ready ? "hero.ready" : "hero.starting")), h("p", null, t("hero.text"))),
      h(
        "dl",
        { class: "hero-facts" },
        h("div", null, h("dt", null, t("hero.version")), h("dd", null, s.version)),
        h("div", null, h("dt", null, t("hero.uptime")), h("dd", null, fmt.uptime(s.uptime_seconds))),
        h("div", null, h("dt", null, t("hero.https")), h("dd", null, cert)),
      ),
    );

    const errorNote = (engine) =>
      engine.message ? h("p", { class: `note ${engine.status === "error" ? "bad" : ""}` }, engine.message) : null;
    const engines = h(
      "section",
      { class: "grid" },
      engineCard(ICONS.database, "ClamAV", t("engine.clamav"), clamav.status, [
        [t("row.engine"), clamav.engine_version || "—"],
        [t("row.signatures"), clamav.signatures ? fmt.number(clamav.signatures) : "—"],
        [t("row.daily"), daily ? `${daily.version} · ${fmt.relative(daily.built_at)}` : "—"],
        [t("row.next"), clamav.next_check ? fmt.relative(clamav.next_check) : "—"],
      ], errorNote(clamav)),
      engineCard(ICONS.rules, "YARA-X", t("engine.yara"), yara.status, [
        [t("row.rules"), yara.rules ? fmt.number(yara.rules) : "—"],
        [t("row.package"), `YARA Forge ${yara.package}`],
        [t("row.release"), yara.release || "—"],
        [t("row.updated"), fmt.relative(yara.loaded_at)],
      ], errorNote(yara)),
      engineCard(
        ICONS.hash,
        "MalwareBazaar",
        t("engine.bazaar"),
        malwarebazaar.status,
        malwarebazaar.status === "ready" ? [[t("row.cached"), fmt.number(malwarebazaar.cached_hashes)]] : [],
        malwarebazaar.status === "disabled" ? h("p", { class: "note" }, t("bazaar.off")) : null,
      ),
    );

    const scans = s.scans;
    const stat = (label, value, extra = "") => h("div", { class: `card stat ${extra}` }, h("span", null, label), h("strong", null, value));
    const stats = h(
      "section",
      { class: "grid stats" },
      stat(t("stats.scans"), fmt.number(scans.total)),
      stat(t("stats.threats"), fmt.number(scans.malicious + scans.suspicious), scans.malicious + scans.suspicious ? "threats" : ""),
      stat(t("stats.average"), scans.total ? fmt.ms(scans.average_ms) : "—"),
      stat(t("stats.cache"), fmt.number(scans.cache_hits)),
    );

    const recent = s.recent || [];
    const table = recent.length
      ? h(
          "div",
          { class: "table-wrap" },
          h(
            "table",
            null,
            h("thead", null, h("tr", null, [["col.time", "opt"], ["col.file"], ["col.size", "opt"], ["col.verdict"], ["col.threat"], ["col.duration", "opt"]].map(([k, cls]) => h("th", { class: cls || null }, t(k))))),
            h(
              "tbody",
              null,
              recent.map((r) =>
                h(
                  "tr",
                  null,
                  h("td", { class: "num opt" }, fmt.time(r.at)),
                  h("td", { class: "file", title: r.name || r.sha256 }, h("bdi", null, r.name || `${r.sha256.slice(0, 12)}…`)),
                  h("td", { class: "num opt" }, fmt.bytes(r.size)),
                  h("td", null, h("span", { class: `badge v-${r.verdict}` }, t(`verdict.${r.verdict}`))),
                  h("td", null, r.threat ? h("bdi", null, r.threat) : "—"),
                  h("td", { class: "num opt" }, r.cached ? `${fmt.ms(r.duration_ms)} · ${t("result.cached")}` : fmt.ms(r.duration_ms)),
                ),
              ),
            ),
          ),
        )
      : h("p", { class: "empty" }, t("recent.empty"));

    $("#app").replaceChildren(
      h("div", { class: "page" }, hero, engines, protectionCard(s), stats, h("section", { class: "card" }, h("h2", null, t("recent.title")), table)),
    );
  }

  // ---------- scan

  function renderScan() {
    const max = state.status?.limits?.max_file_size;
    const input = h("input", { id: "file", type: "file", class: "sr", onchange: (e) => e.target.files[0] && upload(e.target.files[0]) });
    const zone = h(
      "label",
      {
        class: "dropzone",
        for: "file",
        tabindex: "0",
        onkeydown: (e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            input.click();
          }
        },
        ondragover: (e) => {
          e.preventDefault();
          zone.classList.add("over");
        },
        ondragleave: () => zone.classList.remove("over"),
        ondrop: (e) => {
          e.preventDefault();
          zone.classList.remove("over");
          const file = e.dataTransfer.files[0];
          if (file) upload(file);
        },
      },
      ICONS.upload(),
      h("strong", null, t("scan.drop")),
      h("u", null, t("scan.browse")),
      max ? h("small", { class: "muted" }, t("scan.limit", { size: fmt.bytes(max) })) : null,
    );
    const eicarButton = h(
      "button",
      { class: "btn ghost", type: "button", onclick: () => upload(new File([eicar()], "eicar.com", { type: "application/octet-stream" })) },
      t("scan.eicar"),
    );
    const progress = h(
      "div",
      { class: "progress", id: "progress", hidden: true },
      h("div", { class: "progress-track" }, h("div", { class: "progress-bar", id: "bar" })),
      h("span", { class: "progress-label", id: "progress-label" }),
    );
    const result = h("div", { id: "result" }, state.report ? renderReport(state.report) : null);
    $("#app").replaceChildren(
      h("div", { class: "page" }, h("h1", null, t("scan.title")), h("section", { class: "card" }, zone, input, h("div", { class: "scan-actions" }, eicarButton), progress), result),
    );
  }

  function setProgress(fraction, label) {
    const box = $("#progress");
    if (!box) return;
    box.hidden = false;
    const bar = $("#bar");
    bar.classList.toggle("indeterminate", fraction === null);
    if (fraction !== null) bar.style.width = `${Math.round(fraction * 100)}%`;
    $("#progress-label").textContent = label;
  }

  function upload(file) {
    if (state.busy) return;
    state.busy = true;
    state.report = null;
    $("#result")?.replaceChildren();
    const form = new FormData();
    form.append("file", file, file.name);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/v1/scan");
    xhr.setRequestHeader("X-FileFender-CSRF", "1");
    xhr.responseType = "json";
    const percent = (f) => new Intl.NumberFormat(state.lang, { style: "percent" }).format(f);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) setProgress(e.loaded / e.total, t("scan.uploading", { percent: percent(e.loaded / e.total) }));
    };
    xhr.upload.onload = () => setProgress(null, t("scan.scanning"));
    const finish = (render) => {
      state.busy = false;
      const box = $("#progress");
      if (box) box.hidden = true;
      render();
    };
    xhr.onload = () =>
      finish(() => {
        if (xhr.status === 401) return sessionEnded();
        if (xhr.status === 200 && xhr.response) {
          state.report = xhr.response;
          $("#result")?.replaceChildren(renderReport(state.report));
          refreshStatus();
          return;
        }
        const message = xhr.response?.error?.message || `HTTP ${xhr.status}`;
        $("#result")?.replaceChildren(h("p", { class: "callout" }, t("scan.failed", { message })));
      });
    xhr.onerror = () => finish(() => $("#result")?.replaceChildren(h("p", { class: "callout" }, t("signin.offline"))));
    setProgress(0, t("scan.uploading", { percent: percent(0) }));
    xhr.send(form);
  }

  function copyButton(text) {
    const button = h("button", { class: "btn ghost small", type: "button" }, ICONS.copy(), t("result.copy"));
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        button.lastChild.textContent = t("result.copied");
        setTimeout(() => (button.lastChild.textContent = t("result.copy")), 1500);
      } catch {
        /* clipboard unavailable over plain HTTP */
      }
    });
    return button;
  }

  const engineName = (name) =>
    ({ clamav: "ClamAV", yara: "YARA-X", malwarebazaar: "MalwareBazaar", policy: t("engine.policyName"), blocklist: t("engine.blocklistName") })[name] || name;

  // Lets the administrator decide for this exact file from now on.
  function listActions(r) {
    const status = h("span", { class: "status-line", role: "status" });
    const done = (ok, text) => {
      status.className = `status-line ${ok ? "ok" : "bad"}`;
      status.textContent = text;
      state.lists = null;
    };
    const add = async (list) => {
      try {
        const note = [...(r.file.name || "")].slice(0, 200).join("");
        const result = await api("POST", "/v1/hashlist", { sha256: r.file.sha256, list, note });
        done(result.ok, result.ok ? t(list === "allow" ? "result.allowed" : "result.blocked") : result.message);
      } catch {
        /* the session ended */
      }
    };
    if (r.listed) {
      const remove = async () => {
        try {
          const result = await api("DELETE", `/v1/hashlist/${r.file.sha256}`);
          done(result.ok, result.ok ? t("result.unlisted") : result.message);
        } catch {
          /* the session ended */
        }
      };
      return [
        h("button", { class: "btn ghost small", type: "button", onclick: remove }, t("result.unlist")),
        status,
      ];
    }
    return [
      r.verdict !== "malicious" ? h("button", { class: "btn danger small", type: "button", onclick: () => add("block") }, t("result.block")) : null,
      r.verdict !== "clean" ? h("button", { class: "btn ghost small", type: "button", onclick: () => add("allow") }, t("result.allow")) : null,
      status,
    ];
  }

  function renderReport(r) {
    const verdictIcon = { clean: ICONS.check, suspicious: ICONS.alert, malicious: ICONS.cross }[r.verdict];
    const fact = (label, value, wide) => h("div", { class: wide ? "wide" : null }, h("dt", null, label), h("dd", null, value));
    const facts = h(
      "dl",
      { class: "facts" },
      fact(t("result.file"), h("bdi", null, r.file.name || "—")),
      fact(t("result.size"), fmt.bytes(r.file.size)),
      fact(t("result.type"), r.file.type || "—"),
      fact(t("result.duration"), r.cached ? `${fmt.ms(r.duration_ms)} · ${t("result.cached")}` : fmt.ms(r.duration_ms)),
      fact("SHA-256", h("div", { class: "hash-row" }, h("code", { class: "hash", dir: "ltr" }, r.file.sha256), copyButton(r.file.sha256)), true),
    );
    const threats = r.threats.length
      ? [
          h("h3", null, t("result.threats")),
          h(
            "div",
            { class: "table-wrap inline" },
            h(
              "table",
              null,
              h("thead", null, h("tr", null, ["col.engine", "col.name", "col.severity", "col.details"].map((k) => h("th", null, t(k))))),
              h(
                "tbody",
                null,
                r.threats.map((threat) =>
                  h(
                    "tr",
                    null,
                    h("td", null, engineName(threat.engine)),
                    h("td", null, h("code", { dir: "ltr" }, threat.name)),
                    h("td", null, h("span", { class: `badge v-${threat.severity}` }, t(`verdict.${threat.severity}`))),
                    h(
                      "td",
                      { class: "threat-details" },
                      [threat.description, threat.score !== undefined ? `score ${threat.score}` : null].filter(Boolean).join(" · ") || "—",
                      threat.reference ? h("a", { href: threat.reference, target: "_blank", rel: "noopener noreferrer" }, "↗") : null,
                    ),
                  ),
                ),
              ),
            ),
          ),
        ]
      : null;
    const engines = h(
      "ul",
      { class: "engines" },
      ["clamav", "yara", "malwarebazaar", "policy"]
        .filter((name) => r.engines[name])
        .map((name) => [name, r.engines[name]])
        .map(([name, engine]) =>
        h(
          "li",
          null,
          h("strong", null, engineName(name)),
          h("span", { class: `badge e-${engine.status}` }, t(`engine.${engine.status}`)),
          engine.version ? h("span", { class: "muted" }, engine.version) : null,
        ),
      ),
    );
    return h(
      "article",
      { class: "card report" },
      h("div", { class: `verdict v-${r.verdict}` }, verdictIcon(), h("div", null, h("h2", null, t(`result.${r.verdict}.title`)), h("p", null, t(`result.${r.verdict}.text`)))),
      facts,
      r.listed ? h("p", { class: "note" }, t(`result.listed.${r.listed}`)) : null,
      threats,
      h("h3", null, t("result.engines")),
      engines,
      h(
        "div",
        { class: "report-actions" },
        h("button", { class: "btn", type: "button", onclick: () => $("#file")?.click() }, ICONS.upload(), t("scan.again")),
        listActions(r),
      ),
    );
  }

  // ---------- API page

  function codeBlock(title, text, method) {
    return h(
      "div",
      { class: "code-block" },
      h("div", { class: "code-head" }, h("h3", null, title), method ? h("span", { class: "method" }, method) : copyButton(text)),
      h("pre", { class: "code" }, h("code", null, text)),
    );
  }

  function renderApi() {
    if (state.keys === null) loadKeys();
    const base = location.origin;
    const multipart = `curl -H "Authorization: Bearer $FILEFENDER_KEY" \\\n     -F "file=@invoice.pdf" \\\n     ${base}/v1/scan`;
    const raw = `curl -H "Authorization: Bearer $FILEFENDER_KEY" \\\n     -H "Content-Type: application/octet-stream" \\\n     --data-binary @invoice.pdf \\\n     "${base}/v1/scan?filename=invoice.pdf"`;
    const response = JSON.stringify(
      {
        verdict: "malicious",
        file: { name: "invoice.pdf", size: 48213, sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", type: "application/pdf" },
        threats: [{ engine: "clamav", name: "Pdf.Exploit.CVE_2018_4993-6", severity: "malicious" }],
        engines: { clamav: { status: "ok", version: "1.5.4" }, yara: { status: "ok" }, malwarebazaar: { status: "disabled" } },
        cached: false,
        duration_ms: 41,
        scanned_at: "2026-10-08T09:12:44Z",
      },
      null,
      2,
    );
    const cli = "docker exec filefender filefender keys create my-backend\ndocker exec filefender filefender keys list\ndocker exec filefender filefender keys revoke my-backend";
    const endpoints = [
      ["POST", "/v1/scan", t("ep.scan")],
      ["GET", "/v1/hashes/{sha256}", t("ep.hash")],
      ["GET", "/v1/status", t("ep.status")],
      ["GET", "/metrics", t("ep.metrics")],
      ["GET", "/healthz · /readyz", t("ep.health")],
    ];
    $("#app").replaceChildren(
      h(
        "div",
        { class: "page" },
        h("h1", null, t("api.title")),
        h("p", { class: "callout" }, t("api.intro")),
        keysCard(),
        h(
          "section",
          { class: "card" },
          h("h2", null, t("api.endpoints")),
          h(
            "div",
            { class: "table-wrap" },
            h("table", null, h("tbody", null, endpoints.map(([m, path, text]) => h("tr", null, h("td", null, h("span", { class: "method" }, m)), h("td", null, h("code", { dir: "ltr" }, path)), h("td", null, text))))),
          ),
        ),
        h("section", { class: "card grid" }, codeBlock(t("api.multipart"), multipart), codeBlock(t("api.raw"), raw)),
        h("section", { class: "card grid" }, codeBlock(t("api.response"), response, "200 OK"), codeBlock(t("keys.cli"), cli)),
      ),
    );
  }

  async function loadKeys() {
    try {
      const result = await api("GET", "/v1/keys");
      if (!result.ok) return;
      state.keys = result.data.keys;
    } catch {
      return;
    }
    if (state.page === "api") renderApi();
  }

  function keysCard() {
    const label = input({ placeholder: t("keys.placeholder"), maxlength: "64", required: true });
    const error = h("p", { class: "form-error", role: "alert" });
    const submit = h("button", { class: "btn", type: "submit" }, t("keys.create"));
    const form = h(
      "form",
      {
        class: "inline-form",
        onsubmit: async (event) => {
          event.preventDefault();
          error.textContent = "";
          submit.disabled = true;
          try {
            const result = await api("POST", "/v1/keys", { label: label.value });
            if (result.ok) {
              state.newKey = result.data;
              return loadKeys();
            }
            error.textContent = result.message || t("signin.offline");
          } catch {
            /* the session ended */
          }
          submit.disabled = false;
        },
      },
      field(t("keys.label"), label),
      submit,
    );
    const created = state.newKey
      ? h(
          "div",
          { class: "secret-box" },
          h("p", null, t("keys.created")),
          h("div", { class: "hash-row" }, h("code", { class: "hash", dir: "ltr" }, state.newKey.secret), copyButton(state.newKey.secret)),
        )
      : null;
    const revoke = async (key) => {
      if (!window.confirm(t("keys.confirmRevoke", { label: key.label }))) return;
      try {
        const result = await api("DELETE", `/v1/keys/${encodeURIComponent(key.id)}`);
        if (!result.ok) {
          error.textContent = result.message || t("signin.offline");
          return;
        }
        if (state.newKey?.id === key.id) state.newKey = null;
        loadKeys();
      } catch {
        /* the session ended */
      }
    };
    let list = null;
    if (state.keys?.length) {
      list = h(
        "div",
        { class: "table-wrap inline" },
        h(
          "table",
          null,
          h(
            "thead",
            null,
            h("tr", null, h("th", null, t("col.name")), h("th", { class: "opt" }, t("col.lastUsed")), h("th", null, t("col.restrictions")), h("th", { class: "opt" }, t("col.created")), h("th")),
          ),
          h(
            "tbody",
            null,
            state.keys.map((key) => [
              h(
                "tr",
                null,
                h("td", { class: "file" }, h("bdi", null, key.label), h("div", { class: "muted small-id" }, h("code", { dir: "ltr" }, key.id))),
                h("td", { class: "num opt" }, key.last_used_at ? [fmt.relative(key.last_used_at), h("div", { class: "muted" }, h("bdi", { dir: "ltr" }, key.last_ip || ""))] : t("time.never")),
                h("td", null, restrictionTags(key)),
                h("td", { class: "num opt" }, fmt.date(key.created_at)),
                h(
                  "td",
                  { class: "actions" },
                  h("button", { class: "btn ghost small", type: "button", onclick: () => toggleKeyEditor(key.id) }, t("keys.edit")),
                  " ",
                  h("button", { class: "btn danger small", type: "button", onclick: () => revoke(key) }, t("keys.revoke")),
                ),
              ),
              state.editingKey === key.id ? keyEditor(key) : null,
            ]),
          ),
        ),
      );
    } else if (state.keys) {
      list = h("p", { class: "empty" }, t("keys.empty"));
    }
    return h("section", { class: "card" }, h("h2", null, t("keys.title")), h("p", { class: "muted" }, t("keys.text")), form, error, created, list);
  }

  function restrictionTags(key) {
    const tags = [];
    if (key.expired) tags.push(h("span", { class: "badge a-bad" }, t("keys.expired")));
    else if (key.expires_at) tags.push(h("span", { class: "badge" }, t("keys.expires", { date: fmt.day(key.expires_at) })));
    if (key.allowed_networks?.length) tags.push(h("span", { class: "badge", title: key.allowed_networks.join("\n") }, t("keys.networks", { count: fmt.number(key.allowed_networks.length) })));
    if (key.rate_per_minute) tags.push(h("span", { class: "badge" }, t("keys.rate", { rate: fmt.number(key.rate_per_minute) })));
    return tags.length ? h("div", { class: "tags" }, tags) : h("span", { class: "muted" }, t("keys.unrestricted"));
  }

  function toggleKeyEditor(id) {
    state.editingKey = state.editingKey === id ? null : id;
    renderApi();
  }

  function keyEditor(key) {
    const networks = h("textarea", { rows: "3", dir: "ltr", spellcheck: "false", placeholder: "203.0.113.7\n192.168.1.0/24" }, (key.allowed_networks || []).join("\n"));
    const rate = input({ type: "number", inputmode: "numeric", min: "1", max: "100000", value: key.rate_per_minute ? String(key.rate_per_minute) : "" });
    const expiry = input({ type: "date", value: key.expires_at ? key.expires_at.slice(0, 10) : "" });
    const error = h("p", { class: "form-error", role: "alert" });
    const save = async (event) => {
      event.preventDefault();
      error.textContent = "";
      const body = {
        allowed_networks: networks.value.split(/[\s,]+/).filter(Boolean),
        rate_per_minute: rate.value ? Number(rate.value) : null,
        expires_at: expiry.value ? `${expiry.value}T23:59:59Z` : null,
      };
      try {
        const result = await api("PATCH", `/v1/keys/${encodeURIComponent(key.id)}`, body);
        if (!result.ok) {
          error.textContent = result.message || t("signin.offline");
          return;
        }
        state.editingKey = null;
        loadKeys();
      } catch {
        /* the session ended */
      }
    };
    return h(
      "tr",
      { class: "editor" },
      h(
        "td",
        { colspan: "5" },
        h(
          "form",
          { onsubmit: save },
          h(
            "div",
            { class: "fields" },
            field(t("keys.networksField"), networks, t("keys.networksHint")),
            field(t("keys.rateField"), rate, t("keys.rateHint")),
            field(t("keys.expiryField"), expiry, t("keys.expiryHint")),
          ),
          error,
          h(
            "div",
            { class: "inline-actions" },
            h("button", { class: "btn", type: "submit" }, t("keys.save")),
            h("button", { class: "btn ghost", type: "button", onclick: () => toggleKeyEditor(key.id) }, t("common.cancel")),
          ),
        ),
      ),
    );
  }

  // ---------- account

  function qrCode(rows) {
    const quiet = 4;
    const size = rows.length + quiet * 2;
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", `0 0 ${size} ${size}`);
    svg.setAttribute("class", "qr");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "QR code");
    svg.setAttribute("shape-rendering", "crispEdges");
    const background = document.createElementNS(SVG, "rect");
    background.setAttribute("width", String(size));
    background.setAttribute("height", String(size));
    background.setAttribute("fill", "#fff");
    let d = "";
    rows.forEach((row, y) => {
      for (let x = 0; x < row.length; x += 1) if (row[x] === "1") d += `M${x + quiet} ${y + quiet}h1v1h-1z`;
    });
    const modules = document.createElementNS(SVG, "path");
    modules.setAttribute("d", d);
    modules.setAttribute("fill", "#000");
    svg.append(background, modules);
    return svg;
  }

  function failure(result) {
    const known = { invalid_code: "login.badCode", wrong_password: "account.wrongPassword", too_many_failures: "login.throttled" }[result.code];
    return known ? t(known) : result.message || t("signin.offline");
  }

  function renderAccount() {
    const current = input({ type: "password", autocomplete: "current-password", required: true });
    const next = input({ type: "password", autocomplete: "new-password", required: true });
    const confirm = input({ type: "password", autocomplete: "new-password", required: true });
    const message = h("p", { class: "form-error", role: "alert" });
    const submit = h("button", { class: "btn", type: "submit" }, t("account.passwordSubmit"));
    const passwordForm = h(
      "form",
      {
        class: "form",
        onsubmit: async (event) => {
          event.preventDefault();
          message.className = "form-error";
          message.textContent = "";
          if (!longEnough(next.value)) {
            message.textContent = t("password.hint");
            return;
          }
          if (next.value !== confirm.value) {
            message.textContent = t("password.mismatch");
            return;
          }
          submit.disabled = true;
          try {
            const result = await api("POST", "/v1/account/password", { current: current.value, new: next.value });
            if (result.ok) {
              state.user = result.data;
              passwordForm.reset();
              message.className = "form-ok";
              message.textContent = t("account.passwordDone");
            } else {
              message.textContent = failure(result);
            }
          } catch {
            /* the session ended */
          }
          submit.disabled = false;
        },
      },
      field(t("field.current"), current),
      field(t("field.new"), next, t("password.hint")),
      field(t("field.confirm"), confirm),
      message,
      h("div", null, submit),
    );
    const totp = h("div", { class: "form" });
    renderTotp(totp);
    $("#app").replaceChildren(
      h(
        "div",
        { class: "page" },
        h("h1", null, t("account.title")),
        h("p", { class: "muted" }, t("account.signedIn", { name: state.user.username }), " ", t("account.roleIs", { role: t(`role.${state.user.role}`) })),
        h(
          "section",
          { class: "grid" },
          h("section", { class: "card" }, h("h2", null, t("account.password")), passwordForm),
          h("section", { class: "card" }, h("h2", null, t("totp.title")), totp),
        ),
        can("admin") ? usersCard() : null,
      ),
    );
  }

  // ---------- accounts (administrators)

  async function loadUsers(notice) {
    try {
      const result = await api("GET", "/v1/users");
      if (!result.ok) return;
      state.users = result.data.users;
    } catch {
      return;
    }
    $("#s-users")?.replaceWith(usersCard(notice));
  }

  function roleSelect(value) {
    return h("select", null, ROLES.map((role) => h("option", { value: role, selected: role === value || undefined }, t(`role.${role}`))));
  }

  function userFailure(result) {
    const known = { username_taken: "users.taken", too_many_accounts: "users.full" }[result.code];
    return known ? t(known) : result.message || t("signin.offline");
  }

  function toggleUserEditor(id) {
    state.editingUser = state.editingUser === id ? null : id;
    $("#s-users")?.replaceWith(usersCard());
  }

  function usersCard(notice) {
    if (state.users === null) loadUsers();
    const username = input({ autocomplete: "off", maxlength: "64", required: true });
    const password = input({ type: "password", autocomplete: "new-password", required: true });
    const role = roleSelect("operator");
    const error = h("p", { class: "form-error", role: "alert" });
    const submit = h("button", { class: "btn", type: "submit" }, t("users.add"));
    const form = h(
      "form",
      {
        class: "inline-form",
        onsubmit: async (event) => {
          event.preventDefault();
          error.textContent = "";
          if (!longEnough(password.value)) {
            error.textContent = t("password.hint");
            return;
          }
          submit.disabled = true;
          try {
            const result = await api("POST", "/v1/users", { username: username.value, password: password.value, role: role.value });
            if (result.ok) return loadUsers({ ok: true, text: t("users.added", { name: result.data.username }) });
            error.textContent = userFailure(result);
          } catch {
            /* the session ended */
          }
          submit.disabled = false;
        },
      },
      field(t("field.username"), username),
      field(t("field.password"), password),
      field(t("users.role"), role),
      submit,
    );
    let list = h("p", { class: "muted" }, t("common.loading"));
    if (state.users) {
      list = h(
        "div",
        { class: "table-wrap inline" },
        h(
          "table",
          null,
          h(
            "thead",
            null,
            h("tr", null, h("th", null, t("users.col.name")), h("th", null, t("users.role")), h("th", { class: "opt" }, t("users.col.totp")), h("th", { class: "opt" }, t("users.col.lastSignIn")), h("th")),
          ),
          h(
            "tbody",
            null,
            state.users.map((user) => [
              h(
                "tr",
                null,
                h("td", { class: "file" }, h("bdi", null, user.username), user.me ? [" ", h("span", { class: "badge" }, t("users.you"))] : null),
                h("td", null, h("span", { class: `badge r-${user.role}` }, t(`role.${user.role}`))),
                h("td", { class: "opt" }, t(user.totp ? "users.totpOn" : "users.totpOff")),
                h("td", { class: "num opt" }, fmt.relative(user.last_sign_in)),
                h(
                  "td",
                  { class: "actions" },
                  user.me ? null : h("button", { class: "btn ghost small", type: "button", "aria-expanded": String(state.editingUser === user.id), onclick: () => toggleUserEditor(user.id) }, t("users.manage")),
                ),
              ),
              state.editingUser === user.id ? userEditor(user) : null,
            ]),
          ),
        ),
      );
    }
    const legend = h(
      "dl",
      { class: "rows compact roles" },
      [...ROLES].reverse().map((r) => [h("dt", null, t(`role.${r}`)), h("dd", null, t(`role.${r}.hint`))]),
    );
    return h(
      "section",
      { class: "card", id: "s-users" },
      h("h2", null, t("users.title")),
      h("p", { class: "muted lead" }, t("users.text")),
      notice ? h("p", { class: notice.ok ? "form-ok notice" : "form-error notice", role: "status" }, notice.text) : null,
      list,
      h("h3", { class: "subhead" }, t("users.addTitle")),
      form,
      error,
      legend,
    );
  }

  function userEditor(user) {
    const error = h("p", { class: "form-error", role: "alert" });
    const done = async (result, text) => {
      if (!result.ok) {
        error.textContent = userFailure(result);
        return;
      }
      state.editingUser = null;
      await loadUsers({ ok: true, text });
    };
    const patch = async (body, text) => {
      error.textContent = "";
      try {
        done(await api("PATCH", `/v1/users/${encodeURIComponent(user.id)}`, body), text);
      } catch {
        /* the session ended */
      }
    };
    const role = roleSelect(user.role);
    const roleForm = h(
      "form",
      {
        class: "inline-form",
        onsubmit: (event) => {
          event.preventDefault();
          patch({ role: role.value }, t("users.roleDone", { name: user.username }));
        },
      },
      field(t("users.role"), role),
      h("button", { class: "btn ghost", type: "submit" }, t("users.saveRole")),
    );
    const password = input({ type: "password", autocomplete: "new-password", required: true });
    const passwordForm = h(
      "form",
      {
        class: "inline-form",
        onsubmit: (event) => {
          event.preventDefault();
          if (!longEnough(password.value)) {
            error.textContent = t("password.hint");
            return;
          }
          patch({ password: password.value }, t("users.passwordDone", { name: user.username }));
        },
      },
      field(t("field.new"), password),
      h("button", { class: "btn ghost", type: "submit" }, t("users.setPassword")),
    );
    const resetTotp = user.totp
      ? h(
          "button",
          {
            class: "btn ghost small",
            type: "button",
            onclick: () => {
              if (window.confirm(t("users.confirmTotp", { name: user.username }))) patch({ reset_totp: true }, t("users.totpDone", { name: user.username }));
            },
          },
          t("users.resetTotp"),
        )
      : null;
    const remove = h(
      "button",
      {
        class: "btn danger small",
        type: "button",
        onclick: async () => {
          if (!window.confirm(t("users.confirmDelete", { name: user.username }))) return;
          error.textContent = "";
          try {
            done(await api("DELETE", `/v1/users/${encodeURIComponent(user.id)}`), t("users.deleted", { name: user.username }));
          } catch {
            /* the session ended */
          }
        },
      },
      t("users.delete"),
    );
    return h(
      "tr",
      { class: "editor" },
      h(
        "td",
        { colspan: "5" },
        h("div", { class: "fields" }, roleForm, passwordForm),
        h("p", { class: "help muted" }, t("users.passwordHint")),
        error,
        h(
          "div",
          { class: "inline-actions" },
          resetTotp,
          remove,
          h("button", { class: "btn ghost small", type: "button", onclick: () => toggleUserEditor(user.id) }, t("common.cancel")),
        ),
      ),
    );
  }

  function renderTotp(box, enrollment) {
    const error = h("p", { class: "form-error", role: "alert" });
    if (state.user.totp) {
      const password = input({ type: "password", autocomplete: "current-password", required: true });
      const code = input({ autocomplete: "one-time-code", maxlength: "16", required: true, dir: "ltr" });
      const form = h(
        "form",
        {
          class: "form",
          onsubmit: async (event) => {
            event.preventDefault();
            error.textContent = "";
            try {
              const result = await api("POST", "/v1/account/totp/disable", { password: password.value, code: code.value });
              if (!result.ok) {
                error.textContent = failure(result);
                return;
              }
              state.user = result.data;
              renderTotp(box);
            } catch {
              /* the session ended */
            }
          },
        },
        h("p", { class: "muted" }, t("totp.disableText")),
        field(t("field.password"), password),
        field(t("field.code"), code, t("login.codeHelp")),
        error,
        h("div", null, h("button", { class: "btn danger", type: "submit" }, t("totp.disable"))),
      );
      box.replaceChildren(
        h("p", { class: "state-on" }, t("totp.on")),
        h("p", { class: "muted" }, t("totp.left", { count: fmt.number(state.user.recovery_codes_left) })),
        form,
      );
      return;
    }
    if (enrollment) {
      const code = input({ autocomplete: "one-time-code", inputmode: "numeric", maxlength: "6", required: true, dir: "ltr" });
      const form = h(
        "form",
        {
          class: "form",
          onsubmit: async (event) => {
            event.preventDefault();
            error.textContent = "";
            try {
              const result = await api("POST", "/v1/account/totp/enable", { code: code.value });
              if (!result.ok) {
                error.textContent = failure(result);
                return;
              }
              const codes = result.data.recovery_codes;
              const session = await api("GET", "/v1/session");
              box.replaceChildren(
                h("p", null, t("totp.recovery")),
                h("ul", { class: "codes" }, codes.map((c) => h("li", null, c))),
                h(
                  "div",
                  { class: "scan-actions start" },
                  copyButton(codes.join("\n")),
                  h(
                    "button",
                    {
                      class: "btn",
                      type: "button",
                      onclick: () => {
                        state.user = session.data;
                        renderTotp(box);
                      },
                    },
                    t("totp.saved"),
                  ),
                ),
              );
            } catch {
              /* the session ended */
            }
          },
        },
        h("p", { class: "muted" }, t("totp.scan")),
        qrCode(enrollment.qr),
        field(t("totp.key"), h("code", { class: "command" }, enrollment.secret.replace(/(.{4})/g, "$1 ").trim())),
        field(t("field.code"), code),
        error,
        h(
          "div",
          { class: "scan-actions start" },
          h("button", { class: "btn", type: "submit" }, t("totp.activate")),
          h("button", { class: "btn ghost", type: "button", onclick: () => renderTotp(box) }, t("common.cancel")),
        ),
      );
      box.replaceChildren(form);
      code.focus();
      return;
    }
    const enable = h(
      "button",
      {
        class: "btn",
        type: "button",
        onclick: async () => {
          error.textContent = "";
          try {
            const result = await api("POST", "/v1/account/totp/setup");
            if (result.ok) renderTotp(box, result.data);
            else error.textContent = failure(result);
          } catch {
            /* the session ended */
          }
        },
      },
      t("totp.enable"),
    );
    box.replaceChildren(h("p", { class: "muted" }, t("totp.off")), error, h("div", null, enable));
  }

  // ---------- settings

  const MB = 1024 * 1024;

  async function loadSettings() {
    try {
      const result = await api("GET", "/v1/settings");
      if (!result.ok) return;
      state.settings = result.data;
      state.draft = structuredClone(result.data.settings);
    } catch {
      return;
    }
    if (state.page === "settings") renderSettings();
  }

  function switchRow(label, hint, checked, onchange, meta) {
    const box = h("input", { type: "checkbox", class: "switch", role: "switch", checked: checked || undefined, onchange: (e) => onchange(e.target.checked) });
    return h(
      "label",
      { class: "switch-row" },
      h("span", { class: "switch-text" }, h("strong", null, label), hint ? h("small", { class: "muted" }, hint) : null, meta || null),
      box,
    );
  }

  // The server checks the ranges and explains what is wrong.
  function numberInput(value, attrs, onchange) {
    return input({
      type: "number",
      inputmode: "numeric",
      value: String(value),
      ...attrs,
      oninput: (e) => {
        if (e.target.value !== "") onchange(Number(e.target.value));
      },
    });
  }

  const withUnit = (control, unit) => h("div", { class: "with-unit" }, control, h("span", null, unit));

  function section(id, title, text, ...content) {
    return h("section", { class: "card", id: `s-${id}` }, h("h2", null, title), text ? h("p", { class: "muted lead" }, text) : null, ...content);
  }

  function updateButton(engine) {
    const status = h("span", { class: "status-line", role: "status" });
    const button = h(
      "button",
      {
        class: "btn ghost small",
        type: "button",
        onclick: async () => {
          button.disabled = true;
          try {
            const result = await api("POST", "/v1/settings/update", { engine });
            status.className = `status-line ${result.ok ? "ok" : "bad"}`;
            status.textContent = result.ok ? t("settings.updateRequested") : result.message;
          } catch {
            /* the session ended */
          }
          button.disabled = false;
        },
      },
      t("settings.updateNow"),
    );
    return h("div", { class: "inline-actions" }, button, status);
  }

  function webhookEditor(hook, index, catalog, rerender) {
    const d = state.draft;
    const kind = h(
      "select",
      {
        onchange: (e) => {
          hook.kind = e.target.value;
          rerender();
        },
      },
      catalog.webhook_kinds.map((k) => h("option", { value: k, selected: hook.kind === k || undefined }, t(`webhook.kind.${k}`))),
    );
    const url = input({
      type: "url",
      dir: "ltr",
      value: hook.url || "",
      placeholder: hook.url_hint ? t("webhook.saved", { hint: hook.url_hint }) : "https://",
      oninput: (e) => (hook.url = e.target.value.trim() || null),
    });
    const events = h(
      "div",
      { class: "chips" },
      catalog.webhook_events.map((name) =>
        h(
          "label",
          { class: "chip" },
          h("input", {
            type: "checkbox",
            checked: hook.events.includes(name) || undefined,
            onchange: (e) => {
              hook.events = e.target.checked ? [...new Set([...hook.events, name])] : hook.events.filter((x) => x !== name);
            },
          }),
          t(`webhook.event.${name}`),
        ),
      ),
    );
    const status = h("span", { class: "status-line", role: "status" });
    const test = h(
      "button",
      {
        class: "btn ghost small",
        type: "button",
        onclick: async () => {
          test.disabled = true;
          status.className = "status-line";
          status.textContent = "…";
          try {
            const result = await api("POST", "/v1/webhooks/test", { id: hook.id, kind: hook.kind, url: hook.url || undefined });
            status.className = `status-line ${result.ok ? "ok" : "bad"}`;
            status.textContent = result.ok ? t("webhook.delivered", { status: result.data.status }) : result.message;
          } catch {
            /* the session ended */
          }
          test.disabled = false;
        },
      },
      t("webhook.test"),
    );
    const remove = h(
      "button",
      {
        class: "btn danger small",
        type: "button",
        onclick: () => {
          d.webhooks.splice(index, 1);
          rerender();
        },
      },
      t("webhook.remove"),
    );
    // Generic webhooks are signed; the server creates the secret and shows it once.
    let signing = null;
    if (hook.kind === "generic") {
      const toggle = (rotate) =>
        h(
          "button",
          {
            class: "btn ghost small",
            type: "button",
            onclick: () => {
              if (rotate) hook.rotate_secret = true;
              else delete hook.rotate_secret;
              rerender();
            },
          },
          t(rotate ? "webhook.rotate" : "common.cancel"),
        );
      let line = [h("span", { class: "muted" }, t("webhook.signedNew"))];
      if (hook.secret_set && hook.rotate_secret) line = [h("span", { class: "muted" }, t("webhook.rotating")), toggle(false)];
      else if (hook.secret_set) line = [h("span", { class: "state-on" }, t("webhook.signed")), toggle(true)];
      const secret = state.newSecrets?.[hook.id];
      signing = [
        h("div", { class: "hook-actions" }, line),
        secret
          ? h(
              "div",
              { class: "secret-box" },
              h("p", null, t("webhook.secretOnce")),
              h("div", { class: "hash-row" }, h("code", { class: "hash", dir: "ltr" }, secret), copyButton(secret)),
            )
          : null,
      ];
    }
    return h(
      "div",
      { class: "hook" },
      h("div", { class: "hook-top" }, field(t("webhook.kind"), kind), field(t("webhook.url"), url)),
      h("div", { class: "group" }, h("span", { class: "group-label" }, t("webhook.events")), events),
      signing,
      h("div", { class: "hook-actions" }, test, remove, status),
    );
  }

  function renderSettings(message) {
    if (!state.settings) {
      loadSettings();
      $("#app").replaceChildren(h("div", { class: "page" }, h("h1", null, t("settings.title")), h("p", { class: "muted" }, t("common.loading"))));
      return;
    }
    const scroll = window.scrollY;
    const d = state.draft;
    const catalog = state.settings.catalog;
    const clamav = state.status?.engines?.clamav || {};
    const yara = state.status?.engines?.yara || {};
    const rerender = () => renderSettings();

    const nav = h(
      "nav",
      { class: "settings-nav", "aria-label": t("settings.title") },
      [
        ["updates", "settings.updates"],
        ["feeds", "settings.feeds"],
        ["detection", "settings.detection"],
        ["yara", "settings.yara"],
        ["bazaar", "settings.bazaar"],
        ["limits", "settings.limits"],
        ["policy", "settings.policy"],
        ["alerts", "settings.alerts"],
        ["access", "settings.access"],
      ].map(([id, key]) =>
        h(
          "a",
          {
            href: `#s-${id}`,
            onclick: (e) => {
              e.preventDefault();
              document.getElementById(`s-${id}`)?.scrollIntoView({ behavior: "smooth" });
            },
          },
          t(key),
        ),
      ),
    );

    const c = d.clamav;
    const databases = (clamav.databases || []).map((db) => [db.name, `${db.version} · ${fmt.relative(db.built_at)}`]);
    const updates = section(
      "updates",
      t("settings.updates"),
      t("settings.updatesText"),
      h(
        "div",
        { class: "fields" },
        field(t("settings.interval"), withUnit(numberInput(c.update_interval_hours, { min: "1", max: "24" }, (v) => (c.update_interval_hours = v)), t("unit.hours")), t("settings.intervalHint")),
        field(
          t("settings.mirror"),
          input({ value: c.private_mirror || "", dir: "ltr", placeholder: "https://clamav.example.com", oninput: (e) => (c.private_mirror = e.target.value.trim() || null) }),
          t("settings.mirrorHint"),
        ),
      ),
      h(
        "dl",
        { class: "rows compact" },
        [...databases, [t("row.lastCheck"), fmt.relative(clamav.last_check)], [t("row.next"), clamav.next_check ? fmt.relative(clamav.next_check) : "—"]].map(([label, value]) => [
          h("dt", null, label),
          h("dd", null, value),
        ]),
      ),
      updateButton("clamav"),
    );

    const feeds = section(
      "feeds",
      t("settings.feeds"),
      t("settings.feedsText"),
      h(
        "div",
        { class: "switches" },
        catalog.feeds.map((feed) => {
          const live = (clamav.feeds || []).find((f) => f.id === feed.id);
          const enabled = d.feeds.includes(feed.id);
          let progress = null;
          if (enabled && live?.enabled) {
            progress = live.files ? t("feeds.state", { files: live.files, total: live.expected, when: fmt.relative(live.updated_at) }) : t("feeds.pending");
          }
          const meta = h(
            "span",
            { class: "switch-meta" },
            h("a", { href: feed.homepage, target: "_blank", rel: "noopener noreferrer" }, new URL(feed.homepage).host),
            h("span", { dir: "ltr" }, feed.files.join(" · ")),
            progress ? h("span", null, progress) : null,
          );
          return switchRow(
            t(`feed.${feed.id}.title`),
            t(`feed.${feed.id}.text`),
            enabled,
            (on) => {
              d.feeds = on ? [...new Set([...d.feeds, feed.id])] : d.feeds.filter((id) => id !== feed.id);
            },
            meta,
          );
        }),
      ),
      updateButton("clamav"),
    );

    const detect = (key, prop) => switchRow(t(`detect.${key}`), t(`detect.${key}Hint`), c[prop], (on) => (c[prop] = on));
    const detection = section(
      "detection",
      t("settings.detection"),
      t("settings.detectionText"),
      h(
        "div",
        { class: "switches" },
        detect("encrypted", "alert_encrypted"),
        detect("macros", "alert_macros"),
        detect("pua", "detect_pua"),
        detect("heuristics", "heuristics"),
        detect("broken", "broken_executables"),
        detect("phishing", "phishing"),
      ),
      h(
        "div",
        { class: "fields" },
        field(t("detect.recursion"), numberInput(c.max_recursion, { min: "1", max: "64" }, (v) => (c.max_recursion = v))),
        field(t("detect.files"), numberInput(c.max_files, { min: "100", max: "1000000" }, (v) => (c.max_files = v))),
      ),
    );

    const y = d.yara;
    const yaraSection = section(
      "yara",
      t("settings.yara"),
      t("settings.yaraText"),
      h(
        "div",
        { class: "switches" },
        switchRow(t("yara.enabled"), t("yara.enabledHint"), y.enabled, (on) => {
          y.enabled = on;
          rerender();
        }),
      ),
      y.enabled
        ? [
            h(
              "div",
              { class: "fields" },
              field(
                t("yara.package"),
                h(
                  "select",
                  { onchange: (e) => (y.package = e.target.value) },
                  catalog.yara_packages.map((p) => h("option", { value: p, selected: y.package === p || undefined }, t(`yara.${p}`))),
                ),
              ),
              field(t("yara.score"), numberInput(y.malicious_score, { min: "0", max: "100" }, (v) => (y.malicious_score = v)), t("yara.scoreHint")),
              field(t("yara.interval"), withUnit(numberInput(y.update_interval_hours, { min: "6", max: "168" }, (v) => (y.update_interval_hours = v)), t("unit.hours"))),
            ),
            state.settings.custom_yara_url ? h("p", { class: "note" }, t("yara.custom")) : null,
            yara.rules ? h("p", { class: "status-line" }, t("yara.state", { rules: fmt.number(yara.rules), release: yara.release || "—" })) : null,
            updateButton("yara"),
          ]
        : null,
    );

    const b = d.malwarebazaar;
    const removing = b.auth_key === "";
    const key = input({
      type: "password",
      autocomplete: "off",
      dir: "ltr",
      placeholder: t(b.auth_key_set ? "bazaar.keySaved" : "bazaar.keyPlaceholder"),
      oninput: (e) => (b.auth_key = e.target.value.trim() || (removing ? "" : null)),
    });
    const bazaar = section(
      "bazaar",
      t("settings.bazaar"),
      t("settings.bazaarText"),
      h("div", { class: "switches" }, switchRow(t("bazaar.enabled"), t("bazaar.enabledHint"), b.enabled, (on) => (b.enabled = on))),
      h("div", { class: "fields" }, field(t("bazaar.key"), key)),
      h(
        "div",
        { class: "inline-actions" },
        h("a", { href: "https://auth.abuse.ch/", target: "_blank", rel: "noopener noreferrer" }, t("bazaar.getKey")),
        b.auth_key_set
          ? h(
              "button",
              {
                class: "btn danger small",
                type: "button",
                onclick: () => {
                  b.auth_key = "";
                  b.auth_key_set = false;
                  b.enabled = false;
                  rerender();
                },
              },
              t("bazaar.removeKey"),
            )
          : null,
      ),
    );

    const l = d.limits;
    const limits = section(
      "limits",
      t("settings.limits"),
      t("settings.limitsText"),
      h(
        "div",
        { class: "fields" },
        field(t("limits.size"), withUnit(numberInput(Math.max(1, Math.round(l.max_file_size / MB)), { min: "1", max: "2048" }, (v) => (l.max_file_size = Math.round(v * MB))), t("unit.mb"))),
        field(t("limits.timeout"), withUnit(numberInput(l.scan_timeout_seconds, { min: "10", max: "1800" }, (v) => (l.scan_timeout_seconds = v)), t("unit.seconds")), t("limits.timeoutHint")),
        field(t("limits.cache"), withUnit(numberInput(l.cache_ttl_minutes, { min: "0", max: "10080" }, (v) => (l.cache_ttl_minutes = v)), t("unit.minutes")), t("limits.cacheHint")),
      ),
    );

    const p = d.policy;
    const policy = section(
      "policy",
      t("settings.policy"),
      t("settings.policyText"),
      h("div", { class: "switches" }, switchRow(t("policy.disguised"), t("policy.disguisedHint"), p.disguised_files, (on) => (p.disguised_files = on))),
      h("h3", { class: "subhead" }, t("policy.blockTitle")),
      h(
        "div",
        { class: "switches" },
        catalog.policy_categories.map((category) =>
          switchRow(t(`policy.${category}`), t(`policy.${category}.hint`), p.blocked.includes(category), (on) => {
            p.blocked = on ? [...new Set([...p.blocked, category])] : p.blocked.filter((x) => x !== category);
          }),
        ),
      ),
    );

    const alerts = section(
      "alerts",
      t("settings.alerts"),
      t("settings.alertsText"),
      h("div", { class: "hooks" }, d.webhooks.length ? d.webhooks.map((hook, index) => webhookEditor(hook, index, catalog, rerender)) : h("p", { class: "empty" }, t("webhook.empty"))),
      h(
        "div",
        { class: "inline-actions" },
        h(
          "button",
          {
            class: "btn ghost",
            type: "button",
            onclick: () => {
              d.webhooks.push({ kind: "discord", url: null, events: [...catalog.webhook_events] });
              rerender();
            },
          },
          t("webhook.add"),
        ),
      ),
    );

    const ip = state.settings.client_ip;
    const networks = h(
      "textarea",
      {
        rows: "4",
        dir: "ltr",
        spellcheck: "false",
        placeholder: "203.0.113.7\n192.168.1.0/24",
        oninput: (e) => (d.dashboard.allowed_networks = e.target.value.split(/[\s,]+/).filter(Boolean)),
      },
      d.dashboard.allowed_networks.join("\n"),
    );
    const access = section(
      "access",
      t("settings.access"),
      t("settings.accessText"),
      h("div", { class: "fields" }, field(t("access.networks"), networks, t("access.networksHint"))),
      h(
        "div",
        { class: "inline-actions" },
        h("span", { class: "muted" }, t("access.yourIp", { ip })),
        h(
          "button",
          {
            class: "btn ghost small",
            type: "button",
            onclick: () => {
              if (!d.dashboard.allowed_networks.includes(ip)) d.dashboard.allowed_networks.push(ip);
              rerender();
            },
          },
          t("access.addMine"),
        ),
      ),
      h("p", { class: "help muted" }, t("access.unlock"), h("code", null, "docker exec filefender filefender admin unlock-dashboard")),
    );

    const note = h("p", { class: message && !message.ok ? "form-error" : "form-ok", role: "status" }, message?.text || "");
    const save = h("button", { class: "btn", type: "button", onclick: () => saveSettings(save) }, t("settings.save"));
    const discard = h(
      "button",
      {
        class: "btn ghost",
        type: "button",
        onclick: () => {
          state.draft = structuredClone(state.settings.settings);
          renderSettings();
        },
      },
      t("settings.discard"),
    );
    // The bar appears once something differs from the saved settings.
    const savebar = h("div", { class: "savebar" }, note, discard, save);
    const changed = () => JSON.stringify(state.draft) !== JSON.stringify(state.settings.settings);
    const syncBar = () => {
      savebar.hidden = !changed() && !note.textContent;
      discard.hidden = !changed();
    };
    syncBar();

    const page = h(
      "div",
      { class: "page", oninput: syncBar, onchange: syncBar },
      h("div", null, h("h1", null, t("settings.title")), h("p", { class: "muted lead" }, t("settings.intro"))),
      nav,
      updates,
      feeds,
      detection,
      yaraSection,
      bazaar,
      limits,
      policy,
      alerts,
      access,
      savebar,
    );
    $("#app").replaceChildren(page);
    window.scrollTo(0, scroll);
  }

  async function saveSettings(button) {
    button.disabled = true;
    try {
      const result = await api("PUT", "/v1/settings", state.draft);
      if (result.ok) {
        const { new_secrets: secrets, ...payload } = result.data;
        state.settings = payload;
        state.draft = structuredClone(payload.settings);
        state.newSecrets = secrets && Object.keys(secrets).length ? secrets : null;
        renderSettings({ ok: true, text: t("settings.saved") });
        refreshStatus();
        return;
      }
      const text = result.code === "lockout" ? t("settings.lockout", { ip: state.settings.client_ip }) : result.message || t("signin.offline");
      renderSettings({ ok: false, text });
    } catch {
      /* the session ended */
    }
  }

  // ---------- SHA-256 lists

  async function loadLists() {
    try {
      const result = await api("GET", "/v1/hashlist");
      if (!result.ok) return;
      state.lists = result.data;
    } catch {
      return;
    }
    $("#s-lists")?.replaceWith(listsCard());
  }

  function listsCard() {
    if (state.lists === null) loadLists();
    const sha = input({ dir: "ltr", maxlength: "64", required: true, pattern: "[0-9a-fA-F]{64}", placeholder: "e3b0c44298fc1c149afbf4c8996fb924…" });
    const kind = h("select", null, h("option", { value: "block" }, t("lists.block")), h("option", { value: "allow" }, t("lists.allow")));
    const note = input({ maxlength: "200", placeholder: t("lists.notePlaceholder") });
    const error = h("p", { class: "form-error", role: "alert" });
    const form = h(
      "form",
      {
        class: "inline-form",
        onsubmit: async (event) => {
          event.preventDefault();
          error.textContent = "";
          try {
            const result = await api("POST", "/v1/hashlist", { sha256: sha.value.trim(), list: kind.value, note: note.value });
            if (!result.ok) {
              error.textContent = result.message || t("signin.offline");
              return;
            }
            loadLists();
          } catch {
            /* the session ended */
          }
        },
      },
      field(t("col.hash"), sha),
      field(t("lists.list"), kind),
      field(t("lists.note"), note),
      h("button", { class: "btn", type: "submit" }, t("lists.add")),
    );
    const remove = async (entry) => {
      try {
        const result = await api("DELETE", `/v1/hashlist/${entry.sha256}`);
        if (result.ok) loadLists();
      } catch {
        /* the session ended */
      }
    };
    const entries = state.lists?.entries || [];
    const shown = entries.slice(0, 200);
    let table = null;
    if (shown.length) {
      table = h(
        "div",
        { class: "table-wrap inline" },
        h(
          "table",
          null,
          h("thead", null, h("tr", null, h("th", null, t("col.hash")), h("th", null, t("col.list")), h("th", { class: "opt" }, t("col.note")), h("th", { class: "opt" }, t("col.added")), h("th"))),
          h(
            "tbody",
            null,
            shown.map((entry) =>
              h(
                "tr",
                null,
                h("td", { title: entry.sha256 }, h("code", { dir: "ltr" }, `${entry.sha256.slice(0, 16)}…`)),
                h("td", null, h("span", { class: `badge l-${entry.list}` }, t(`lists.${entry.list}`))),
                h("td", { class: "detail opt" }, entry.note ? h("bdi", null, entry.note) : "—"),
                h("td", { class: "num opt" }, fmt.relative(entry.added_at)),
                h("td", { class: "actions" }, h("button", { class: "btn danger small", type: "button", onclick: () => remove(entry) }, t("lists.remove"))),
              ),
            ),
          ),
        ),
      );
    } else if (state.lists) {
      table = h("p", { class: "empty" }, t("lists.empty"));
    }
    return h(
      "section",
      { class: "card", id: "s-lists" },
      form,
      error,
      entries.length > shown.length ? h("p", { class: "muted" }, t("lists.more", { count: fmt.number(shown.length) })) : null,
      table,
    );
  }

  function renderLists() {
    $("#app").replaceChildren(
      h("div", { class: "page" }, h("div", null, h("h1", null, t("lists.title")), h("p", { class: "muted lead" }, t("lists.text"))), listsCard()),
    );
  }

  // ---------- activity

  const AUDIT_LEVEL = {
    "session.failed": "a-warn",
    "account.recovery_code_used": "a-warn",
    "dashboard.unlocked": "a-warn",
    "user.role_changed": "a-warn",
    "user.password_reset": "a-warn",
    "security.throttled": "a-bad",
    "account.totp_disabled": "a-bad",
    "user.totp_reset": "a-bad",
    "admin.reset": "a-bad",
  };

  async function loadAudit() {
    try {
      const result = await api("GET", "/v1/audit?limit=200");
      if (!result.ok) return;
      state.audit = result.data.entries;
    } catch {
      return;
    }
    if (state.page === "activity") renderActivity();
  }

  function renderActivity() {
    if (state.audit === null) loadAudit();
    const label = (action) => {
      const text = t(`audit.${action}`);
      return text === `audit.${action}` ? action : text;
    };
    let content = h("p", { class: "muted" }, t("common.loading"));
    if (state.audit?.length) {
      content = h(
        "div",
        { class: "table-wrap" },
        h(
          "table",
          null,
          h(
            "thead",
            null,
            h("tr", null, h("th", null, t("col.time")), h("th", null, t("col.action")), h("th", null, t("col.by")), h("th", { class: "opt" }, t("col.address")), h("th", { class: "opt" }, t("col.details"))),
          ),
          h(
            "tbody",
            null,
            state.audit.map((entry) =>
              h(
                "tr",
                null,
                h("td", { class: "num" }, fmt.date(entry.at)),
                h("td", null, h("span", { class: `badge ${AUDIT_LEVEL[entry.action] || ""}` }, label(entry.action))),
                h("td", { class: "file" }, h("bdi", null, entry.actor)),
                h("td", { class: "num opt" }, h("bdi", { dir: "ltr" }, entry.ip || "—")),
                h("td", { class: "detail opt" }, entry.detail ? h("bdi", null, entry.detail) : "—"),
              ),
            ),
          ),
        ),
      );
    } else if (state.audit) {
      content = h("p", { class: "empty" }, t("activity.empty"));
    }
    const refresh = h(
      "button",
      {
        class: "btn ghost small",
        type: "button",
        onclick: () => {
          state.audit = null;
          renderActivity();
        },
      },
      t("activity.refresh"),
    );
    $("#app").replaceChildren(
      h(
        "div",
        { class: "page" },
        h("div", { class: "section-title" }, h("h1", null, t("activity.title")), refresh),
        h("p", { class: "muted lead" }, t("activity.text")),
        h("section", { class: "card" }, content),
      ),
    );
  }

  // ---------- routing

  function route() {
    if (!state.user) return start();
    const page = location.hash.replace(/^#\//, "") || "dashboard";
    state.page = Object.hasOwn(PAGES, page) && can(PAGES[page]) ? page : "dashboard";
    if (`#/${state.page}` !== location.hash) history.replaceState(null, "", `#/${state.page}`);
    if (state.page !== "api") {
      state.newKey = null;
      state.editingKey = null;
    }
    if (state.page !== "settings") state.newSecrets = null;
    $("#tabs").hidden = false;
    $("#signout").hidden = false;
    for (const link of document.querySelectorAll("#tabs a")) {
      link.hidden = !can(PAGES[link.dataset.page]);
      const active = link.dataset.page === state.page;
      link.classList.toggle("active", active);
      if (active) {
        link.setAttribute("aria-current", "page");
        // On phones the tabs scroll sideways: keep the current one in view.
        const tabs = link.parentElement;
        if (tabs.scrollWidth > tabs.clientWidth) link.scrollIntoView({ block: "nearest", inline: "center" });
      } else link.removeAttribute("aria-current");
    }
    if (state.page === "dashboard") renderDashboard();
    if (state.page === "scan") renderScan();
    if (state.page === "lists") {
      state.lists = null;
      renderLists();
    }
    if (state.page === "api") renderApi();
    if (state.page === "settings") renderSettings();
    if (state.page === "activity") {
      state.audit = null;
      renderActivity();
    }
    if (state.page === "account") {
      state.users = null;
      state.editingUser = null;
      renderAccount();
    }
    if (!state.timer) startPolling();
  }

  function init() {
    const select = $("#lang");
    for (const lang of I18N.languages) select.append(h("option", { value: lang.code }, lang.name));
    select.addEventListener("change", () => setLanguage(select.value));
    $("#signout").append(ICONS.logout());
    $("#signout").addEventListener("click", () => signOut());
    const theme = localStorage.getItem(STORE.theme) || "auto";
    applyTheme(theme);
    $("#theme").addEventListener("click", () => {
      const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      localStorage.setItem(STORE.theme, next);
      applyTheme(next);
    });
    matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => applyTheme(localStorage.getItem(STORE.theme) || "auto"));
    window.addEventListener("hashchange", route);
    setLanguage(detectLanguage(), false);
    start();
  }

  init();
})();

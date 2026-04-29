package center

const centerHTMLTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>TUKUYOMI Center</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --line: #e5e7eb;
      --accent: #2563eb;
      --accent-strong: #1d4ed8;
      --ok-bg: #dcfce7;
      --ok-text: #166534;
      --bad-bg: #fee2e2;
      --bad-text: #991b1b;
    }
    * {
      box-sizing: border-box;
    }
    body {
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at 100% 0%, rgba(233, 176, 116, .12), transparent 20%),
        linear-gradient(180deg, #fafcff 0%, var(--bg) 100%);
      color: var(--text);
      font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main {
      width: min(960px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 40px 0;
    }
    body.is-login #login-main {
      display: flex;
      align-items: center;
      justify-content: center;
      width: min(448px, calc(100vw - 32px));
      min-height: 100vh;
      padding: 0;
    }
    header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      padding-bottom: 20px;
    }
    .eyebrow {
      margin: 0 0 4px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: .12em;
      text-transform: uppercase;
    }
    h1 {
      margin: 0;
      font-size: 28px;
      line-height: 1.15;
    }
    .subtitle {
      margin: 6px 0 0;
      color: var(--muted);
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 8px 24px rgba(15, 23, 42, .06);
      padding: 24px;
    }
    body.is-login .panel {
      border-color: #e5e5e5;
      border-radius: 28px;
      box-shadow: 0 1px 2px rgba(15, 23, 42, .05);
      padding: 32px;
    }
    .grid {
      display: grid;
      grid-template-columns: minmax(260px, 360px) minmax(0, 1fr);
      gap: 24px;
      align-items: start;
    }
    .login-mode {
      width: 100%;
      grid-template-columns: 1fr;
      gap: 0;
    }
    .login-mode #login-form {
      width: 100%;
    }
    .login-card-header {
      display: block;
      margin-bottom: 24px;
    }
    .login-mode .eyebrow {
      margin-bottom: 8px;
      color: #737373;
      letter-spacing: .3em;
    }
    .login-mode h1 {
      font-size: 30px;
      font-weight: 600;
      line-height: 1.1;
    }
    .login-mode .subtitle {
      margin-top: 8px;
      color: #525252;
      font-size: 12px;
    }
    .login-mode .field + .field {
      margin-top: 16px;
    }
    .login-mode label {
      margin-bottom: 8px;
      color: #404040;
      font-size: 12px;
      font-weight: 500;
    }
    .login-mode input {
      height: 36px;
      border-color: #d4d4d4;
      border-radius: 12px;
      padding: 8px 12px;
      background: #ffffff;
      font-size: 12px;
      line-height: 1rem;
    }
    .login-mode input:focus {
      outline: 2px solid rgba(23, 23, 23, .1);
      border-color: #d4d4d4;
    }
    .login-mode .actions {
      margin-top: 16px;
    }
    .login-mode button.primary {
      width: 100%;
      height: 38px;
      border-color: #0a0a0a;
      border-radius: 12px;
      background: #0a0a0a;
      color: #ffffff;
      font-size: 12px;
      font-weight: 500;
    }
    .login-mode button.primary:disabled {
      opacity: .5;
    }
    #login-session-pill {
      display: none;
    }
    .dashboard-mode {
      width: 100%;
    }
    .app-shell {
      display: grid;
      grid-template-columns: 216px minmax(0, 1fr);
      min-height: 100vh;
    }
    .app-sidebar {
      display: flex;
      flex-direction: column;
      position: sticky;
      top: 0;
      height: 100vh;
      overflow-y: auto;
      padding: 12px 10px 14px;
      border-right: 1px solid #e5eaf2;
      background:
        linear-gradient(180deg, rgba(255, 255, 255, .94), rgba(250, 252, 255, .98)),
        #f8fafc;
      color: var(--text);
      box-shadow: inset -1px 0 0 rgba(15, 23, 42, .02);
    }
    .app-brand {
      margin-bottom: 12px;
      padding: 6px 8px 10px;
    }
    .app-brand-tag {
      margin: 0;
      color: #7b8798;
      font-size: 10px;
      letter-spacing: .18em;
    }
    .app-brand h1 {
      margin: 8px 0 3px;
      line-height: 1.08;
      font-size: 1.04rem;
      font-weight: 700;
      word-break: keep-all;
    }
    .app-brand-sub {
      margin: 0;
      color: #7b8798;
      font-size: 10px;
    }
    .app-nav {
      display: grid;
      gap: 8px;
      flex: 1 1 auto;
      align-content: start;
    }
    .app-nav-group {
      display: grid;
      gap: 4px;
      padding: 0;
    }
    .app-nav-group-meta {
      padding: 0 8px 2px;
    }
    .app-nav-group-title {
      margin: 0;
      color: #8391a6;
      border-bottom: 1px solid #e8edf5;
      font-size: 10px;
      letter-spacing: .14em;
      text-transform: uppercase;
    }
    .app-nav-link {
      display: flex;
      align-items: center;
      border: 0;
      border-radius: 0;
      padding: 8px 10px;
      background: transparent;
      color: #334155;
      text-decoration: none;
    }
    .app-nav-link.active {
      background: #eaf1ff;
      color: #1744b3;
    }
    .app-nav-label {
      font-size: 12px;
      font-weight: 600;
    }
    .app-sidebar-footer {
      margin-top: 12px;
      padding-top: 10px;
      border-top: 1px solid #e8edf5;
    }
    .app-main {
      display: grid;
      grid-template-rows: auto 1fr;
      min-width: 0;
      width: auto;
      margin: 0;
      padding: 0;
      background: linear-gradient(180deg, rgba(255, 255, 255, .46), transparent 28%);
    }
    .app-topbar {
      margin: 14px 16px 0;
      padding: 14px 16px 12px;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 18px;
      border: 1px solid #e2e8f0;
      border-radius: 14px;
      background: rgba(255, 255, 255, .96);
      box-shadow: 0 6px 20px rgba(15, 23, 42, .05);
    }
    .app-topbar-main {
      min-width: 0;
      display: grid;
      gap: 10px;
    }
    .app-kicker {
      margin: 0 0 4px;
      color: var(--muted);
      font-size: 10px;
      letter-spacing: .1em;
      text-transform: uppercase;
    }
    .app-group-chip {
      display: inline-flex;
      align-items: center;
      width: fit-content;
      margin: 0 0 5px;
      border: 1px solid #dbe7ff;
      border-radius: 999px;
      padding: 3px 9px;
      background: #eef4ff;
      color: #2457c6;
      font-size: 11px;
      font-weight: 700;
    }
    .app-topbar h2 {
      margin: 0;
      font-size: clamp(1.12rem, 1.95vw, 1.48rem);
      line-height: 1.15;
    }
    .app-topbar-sub {
      margin: 6px 0 0;
      color: var(--muted);
      font-size: 11px;
      max-width: 66ch;
    }
    .app-topbar-paths {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .app-topbar-paths code {
      border: 1px solid #dbe5f0;
      border-radius: 999px;
      padding: 4px 10px;
      background: #f8fbff;
      color: #536170;
      font-size: 12px;
      max-width: min(34vw, 360px);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .app-top-meta {
      display: grid;
      gap: 10px;
      justify-items: end;
      color: var(--muted);
      font-size: 12px;
    }
    .app-top-meta-cluster {
      display: flex;
      flex-wrap: wrap;
      justify-content: flex-end;
      gap: 8px;
    }
    .app-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid #dbe5f0;
      border-radius: 999px;
      padding: 4px 10px;
      background: #f8fbff;
      color: #334155;
      font-weight: 600;
      white-space: nowrap;
    }
    .app-pill-action {
      justify-content: center;
      background: #2563eb;
      border-color: #2563eb;
      color: #eff6ff;
    }
    .app-pill select {
      border: 0;
      padding: 0;
      background: transparent;
      color: inherit;
      font: inherit;
      outline: 0;
    }
    .app-content {
      padding: 14px 16px 18px;
      overflow: auto;
    }
    .app-content > div {
      border: 1px solid #e2e8f0;
      border-radius: 14px;
      background: #ffffff;
      box-shadow: 0 8px 24px rgba(15, 23, 42, .045);
    }
    .content-panel {
      padding: 16px;
    }
    .content-section {
      border: 1px solid #e5e7eb;
      border-radius: 12px;
      background: #ffffff;
      padding: 16px;
    }
    .content-section + .content-section {
      margin-top: 16px;
    }
    label {
      display: block;
      margin: 0 0 6px;
      font-size: 12px;
      font-weight: 700;
    }
    label.app-pill {
      display: inline-flex;
      margin: 0;
      font-size: 12px;
      font-weight: 600;
    }
    input {
      width: 100%;
      height: 38px;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 0 10px;
      background: #fbfffe;
      color: var(--text);
      font: inherit;
    }
    input:focus {
      outline: 2px solid rgba(37, 99, 235, .18);
      border-color: var(--accent);
    }
    .field + .field {
      margin-top: 14px;
    }
    button {
      height: 38px;
      border: 1px solid #bfdbfe;
      border-radius: 6px;
      padding: 0 14px;
      background: #eff6ff;
      color: #1e3a8a;
      cursor: pointer;
      font: inherit;
      font-weight: 700;
      line-height: 1rem;
      white-space: nowrap;
    }
    button.primary {
      border-color: var(--accent);
      background: var(--accent);
      color: #ffffff;
    }
    button.danger {
      border-color: #fecaca;
      background: #fff1f2;
      color: #991b1b;
    }
    button:disabled {
      border-color: #e5e7eb;
      background: #f8fafc;
      color: #94a3b8;
      cursor: not-allowed;
    }
    button:hover {
      border-color: var(--accent-strong);
    }
    button.app-pill {
      height: auto;
      border: 1px solid #dbe5f0;
      border-radius: 999px;
      padding: 4px 10px;
      background: #f8fbff;
      color: #334155;
      box-shadow: none;
      transform: none;
    }
    button.app-pill-action {
      justify-content: center;
      background: #2563eb;
      border-color: #2563eb;
      color: #eff6ff;
    }
    .actions {
      display: flex;
      gap: 10px;
      margin-top: 18px;
    }
    .status {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border-radius: 999px;
      padding: 3px 9px;
      font-size: 12px;
      font-weight: 700;
      background: #e2e8f0;
      color: #334155;
    }
    .status.ok {
      background: var(--ok-bg);
      color: var(--ok-text);
    }
    .status.bad {
      background: var(--bad-bg);
      color: var(--bad-text);
    }
    .message {
      min-height: 22px;
      margin-top: 12px;
      color: var(--bad-text);
      font-size: 12px;
      font-weight: 700;
    }
    .facts {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 220px));
      gap: 12px;
      justify-content: start;
    }
    .fact {
      min-width: 0;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 12px;
      background: #fbfdff;
    }
    .fact span {
      display: block;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }
    .fact strong {
      display: block;
      margin-top: 4px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .section-title {
      margin: 22px 0 10px;
      font-size: 15px;
      line-height: 1.2;
    }
    #session-panel {
      grid-column: 1 / -1;
    }
    .table-wrap {
      border: 1px solid var(--line);
      border-radius: 6px;
      overflow: auto;
      background: #ffffff;
    }
    table {
      width: 100%;
      min-width: 680px;
      border-collapse: collapse;
      table-layout: fixed;
    }
    th,
    td {
      border-bottom: 1px solid var(--line);
      padding: 8px 10px;
      text-align: left;
      vertical-align: middle;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      background: #f8fafc;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    td {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    th:nth-child(1) {
      width: 22%;
    }
    th:nth-child(2) {
      width: 14%;
    }
    th:nth-child(3) {
      width: 28%;
    }
    th:nth-child(4) {
      width: 18%;
    }
    th:last-child {
      width: 160px;
    }
    tr:last-child td {
      border-bottom: 0;
    }
    td.actions-cell {
      width: 160px;
      min-width: 160px;
      overflow: visible;
      text-align: right;
      white-space: nowrap;
    }
    .inline-actions {
      display: inline-flex;
      gap: 8px;
      justify-content: flex-end;
    }
    .empty {
      color: var(--muted);
      padding: 12px;
    }
    .hidden {
      display: none;
    }
    @media (max-width: 720px) {
      main {
        width: min(100vw - 20px, 960px);
        padding: 20px 0;
      }
      body.is-login #login-main {
        width: min(100vw - 20px, 448px);
        padding: 20px 0;
      }
      .app-shell {
        grid-template-columns: 180px minmax(0, 1fr);
      }
      .app-main {
        width: auto;
        margin: 0;
        padding: 0;
      }
      .app-sidebar {
        padding: 10px 8px;
      }
      .app-topbar {
        margin: 12px 12px 0;
        padding: 12px;
      }
      .app-topbar-paths code {
        max-width: 42vw;
      }
      .app-content {
        padding: 12px;
      }
      header {
        display: block;
      }
      .status {
        margin-top: 12px;
      }
      .grid,
      .facts {
        grid-template-columns: 1fr;
      }
      table {
        table-layout: auto;
      }
    }
  </style>
</head>
<body class="is-login">
  <main id="login-main">
    <section id="login-card" class="panel grid login-mode">
      <form id="login-form">
        <div class="login-card-header">
          <div>
            <p class="eyebrow">TUKUYOMI</p>
            <h1>Admin Sign In</h1>
            <p class="subtitle">Sign in with your admin user to create a browser session.</p>
          </div>
          <div id="login-session-pill" class="status">Checking</div>
        </div>
        <div class="field">
          <label for="identifier">Username or email</label>
          <input id="identifier" name="identifier" autocomplete="username" placeholder="admin username or email" required>
        </div>
        <div class="field">
          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password" placeholder="admin password" required>
        </div>
        <div class="actions">
          <button id="login-button" class="primary" type="submit" disabled>Sign In</button>
        </div>
        <div id="message" class="message" aria-live="polite"></div>
      </form>
    </section>
  </main>

  <div id="dashboard-shell" class="app-shell hidden">
    <aside class="app-sidebar">
      <div class="app-brand">
        <p class="app-brand-tag">TUKUYOMI</p>
        <h1>Control Room</h1>
        <p class="app-brand-sub">Fleet Control Plane</p>
      </div>

      <nav class="app-nav" aria-label="primary">
        <section class="app-nav-group" aria-label="Center">
          <div class="app-nav-group-meta">
            <p class="app-nav-group-title">CENTER</p>
          </div>
          <div class="app-nav-group-links">
            <a class="app-nav-link active" href="#status"><span class="app-nav-label">Status</span></a>
            <a class="app-nav-link" href="#device-approvals"><span class="app-nav-label">Device Approvals</span></a>
          </div>
        </section>
      </nav>

      <div class="app-sidebar-footer">
        <a class="app-nav-link" href="#user"><span class="app-nav-label" id="nav-user">User</span></a>
      </div>
    </aside>

    <main class="app-main">
      <header class="app-topbar">
        <div class="app-topbar-main">
          <div class="app-topbar-heading">
            <p class="app-kicker">Current Group</p>
            <p class="app-group-chip">Center</p>
            <h2>Status</h2>
            <p class="app-topbar-sub">Fleet control plane status and device enrollment approvals.</p>
          </div>
          <div class="app-topbar-paths">
            <code id="fact-api">-</code>
            <code>/center-ui</code>
          </div>
        </div>
        <div class="app-top-meta">
          <div class="app-top-meta-cluster">
            <label class="app-pill">
              <span>Language</span>
              <select aria-label="Language">
                <option>English</option>
              </select>
            </label>
            <span class="app-pill" id="session-mode">Session</span>
            <span class="app-pill" id="session-expires">Expires -</span>
          </div>
          <button id="logout-button" type="button" class="app-pill app-pill-action">Logout</button>
        </div>
      </header>

      <section class="app-content">
        <div id="session-panel" class="content-panel hidden">
          <section id="status" class="content-section">
            <div class="facts">
              <div class="fact">
                <span>Total devices</span>
                <strong id="fact-total">-</strong>
              </div>
              <div class="fact">
                <span>Approved devices</span>
                <strong id="fact-approved">-</strong>
              </div>
              <div class="fact">
                <span>Pending approvals</span>
                <strong id="fact-pending">-</strong>
              </div>
              <div class="fact">
                <span>Rejected enrollments</span>
                <strong id="fact-rejected">-</strong>
              </div>
            </div>
            <div class="actions">
              <button id="refresh-button" type="button">Refresh</button>
            </div>
          </section>

          <section id="device-approvals" class="content-section">
            <h2 class="section-title">Device enrollment approvals</h2>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Key</th>
                    <th>Fingerprint</th>
                    <th>Requested</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody id="enrollment-rows"></tbody>
              </table>
              <div id="enrollment-empty" class="empty hidden">No pending enrollments.</div>
            </div>
          </section>
        </div>
      </section>
    </main>
  </div>

  <script>
    const settings = __CENTER_SETTINGS__;
    const loginMain = document.getElementById("login-main");
    const dashboardShell = document.getElementById("dashboard-shell");
    const loginSessionPill = document.getElementById("login-session-pill");
    const loginForm = document.getElementById("login-form");
    const identifierInput = document.getElementById("identifier");
    const passwordInput = document.getElementById("password");
    const loginButton = document.getElementById("login-button");
    const message = document.getElementById("message");
    const sessionPanel = document.getElementById("session-panel");
    const logoutButton = document.getElementById("logout-button");
    const refreshButton = document.getElementById("refresh-button");
    const factAPI = document.getElementById("fact-api");
    const factTotal = document.getElementById("fact-total");
    const factApproved = document.getElementById("fact-approved");
    const factPending = document.getElementById("fact-pending");
    const factRejected = document.getElementById("fact-rejected");
    const navUser = document.getElementById("nav-user");
    const sessionMode = document.getElementById("session-mode");
    const sessionExpires = document.getElementById("session-expires");
    const enrollmentRows = document.getElementById("enrollment-rows");
    const enrollmentEmpty = document.getElementById("enrollment-empty");
    let currentSession = null;

    function cookieValue(name) {
      const prefix = name + "=";
      for (const part of document.cookie.split(";")) {
        const item = part.trim();
        if (item.startsWith(prefix)) {
          return decodeURIComponent(item.slice(prefix.length));
        }
      }
      return "";
    }

    function csrfHeaders(session) {
      const name = session.csrf_cookie_name || "tukuyomi_admin_csrf";
      const header = session.csrf_header_name || "X-CSRF-Token";
      const token = cookieValue(name);
      return token ? {[header]: token} : {};
    }

    function setAuthenticated(session) {
      currentSession = session;
      document.body.classList.remove("is-login");
      document.body.classList.add("is-dashboard");
      loginSessionPill.textContent = "Authenticated";
      loginSessionPill.className = "status ok";
      loginMain.classList.add("hidden");
      dashboardShell.classList.remove("hidden");
      sessionPanel.classList.remove("hidden");
      factAPI.textContent = settings.apiBasePath;
      navUser.textContent = session.user?.username ? "User: " + session.user.username : "User";
      sessionMode.textContent = session.mode === "disabled" ? "Auth Disabled" : "Session";
      sessionExpires.textContent = session.expires_at ? "Expires " + new Date(session.expires_at).toLocaleTimeString() : "Expires -";
      refreshCenterStatus();
    }

    function setLoggedOut(text = "") {
      currentSession = null;
      document.body.classList.add("is-login");
      document.body.classList.remove("is-dashboard");
      loginSessionPill.textContent = "Login required";
      loginSessionPill.className = "status bad";
      loginMain.classList.remove("hidden");
      dashboardShell.classList.add("hidden");
      sessionPanel.classList.add("hidden");
      factAPI.textContent = settings.apiBasePath;
      factTotal.textContent = "-";
      factApproved.textContent = "-";
      factPending.textContent = "-";
      factRejected.textContent = "-";
      navUser.textContent = "User";
      sessionMode.textContent = "Session";
      sessionExpires.textContent = "Expires -";
      enrollmentRows.replaceChildren();
      enrollmentEmpty.classList.add("hidden");
      message.textContent = text;
      refreshLoginButton();
    }

    async function refreshCenterStatus() {
      if (!currentSession) {
        return;
      }
      const [statusResponse, enrollmentsResponse] = await Promise.all([
        fetch(settings.apiBasePath + "/status", {credentials: "same-origin"}),
        fetch(settings.apiBasePath + "/devices/enrollments?status=pending&limit=50", {credentials: "same-origin"})
      ]);
      if (!statusResponse.ok || !enrollmentsResponse.ok) {
        message.textContent = "Failed to load Center status";
        return;
      }
      const status = await statusResponse.json();
      const enrollments = await enrollmentsResponse.json();
      factTotal.textContent = String(status.total_devices ?? 0);
      factApproved.textContent = String(status.approved_devices ?? 0);
      factPending.textContent = String(status.pending_enrollments ?? 0);
      factRejected.textContent = String(status.rejected_enrollments ?? 0);
      renderEnrollments(enrollments.enrollments || []);
    }

    function renderEnrollments(enrollments) {
      enrollmentRows.replaceChildren();
      enrollmentEmpty.classList.toggle("hidden", enrollments.length !== 0);
      for (const item of enrollments) {
        const row = document.createElement("tr");
        row.appendChild(cell(item.device_id || "-"));
        row.appendChild(cell(item.key_id || "-"));
        row.appendChild(cell(item.public_key_fingerprint_sha256 || "-"));
        row.appendChild(cell(formatUnix(item.requested_at_unix)));
        const actions = document.createElement("td");
        actions.className = "actions-cell";
        const actionWrap = document.createElement("div");
        actionWrap.className = "inline-actions";
        const approve = document.createElement("button");
        approve.type = "button";
        approve.textContent = "Approve";
        approve.addEventListener("click", () => decideEnrollment(item.enrollment_id, "approve"));
        const reject = document.createElement("button");
        reject.type = "button";
        reject.className = "danger";
        reject.textContent = "Reject";
        reject.addEventListener("click", () => decideEnrollment(item.enrollment_id, "reject"));
        actionWrap.appendChild(approve);
        actionWrap.appendChild(reject);
        actions.appendChild(actionWrap);
        row.appendChild(actions);
        enrollmentRows.appendChild(row);
      }
    }

    function cell(text) {
      const td = document.createElement("td");
      td.textContent = text;
      td.title = text;
      return td;
    }

    function formatUnix(value) {
      const n = Number(value || 0);
      if (!n) {
        return "-";
      }
      return new Date(n * 1000).toLocaleString();
    }

    async function decideEnrollment(id, action) {
      if (!currentSession || !id) {
        return;
      }
      setDecisionButtonsDisabled(true);
      const response = await fetch(settings.apiBasePath + "/devices/enrollments/" + encodeURIComponent(id) + "/" + action, {
        method: "POST",
        headers: csrfHeaders(currentSession),
        credentials: "same-origin"
      });
      if (!response.ok) {
        message.textContent = "Failed to " + action + " enrollment";
        setDecisionButtonsDisabled(false);
        return;
      }
      message.textContent = "";
      try {
        await refreshCenterStatus();
      } finally {
        setDecisionButtonsDisabled(false);
      }
    }

    function setDecisionButtonsDisabled(disabled) {
      for (const button of enrollmentRows.querySelectorAll("button")) {
        button.disabled = disabled;
      }
    }

    async function loadSession() {
      const response = await fetch(settings.apiBasePath + "/auth/session", {credentials: "same-origin"});
      const session = await response.json();
      if (session.authenticated) {
        setAuthenticated(session);
      } else {
        setLoggedOut("");
      }
      return session;
    }

    loginForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      message.textContent = "";
      loginButton.disabled = true;
      loginButton.textContent = "Signing in...";
      const body = {
        identifier: identifierInput.value,
        password: passwordInput.value
      };
      let response;
      try {
        response = await fetch(settings.apiBasePath + "/auth/login", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          credentials: "same-origin",
          body: JSON.stringify(body)
        });
      } catch {
        loginButton.textContent = "Sign In";
        setLoggedOut("Center API is not reachable");
        return;
      }
      if (!response.ok) {
        loginButton.textContent = "Sign In";
        setLoggedOut("Invalid credentials");
        return;
      }
      passwordInput.value = "";
      loginButton.textContent = "Sign In";
      await loadSession();
    });

    function refreshLoginButton() {
      loginButton.disabled = identifierInput.value.trim() === "" || passwordInput.value.trim() === "";
    }

    identifierInput.addEventListener("input", refreshLoginButton);
    passwordInput.addEventListener("input", refreshLoginButton);

    logoutButton.addEventListener("click", async () => {
      const session = currentSession || await loadSession();
      await fetch(settings.apiBasePath + "/auth/logout", {
        method: "POST",
        headers: csrfHeaders(session),
        credentials: "same-origin"
      });
      setLoggedOut("");
    });

    refreshButton.addEventListener("click", () => {
      refreshCenterStatus().catch(() => {
        message.textContent = "Failed to load Center status";
      });
    });

    loadSession().catch(() => setLoggedOut("Center API is not reachable"));
  </script>
</body>
</html>
`

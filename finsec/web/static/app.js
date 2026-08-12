"use strict";

const content = document.querySelector("#content");
const workspaceSelect = document.querySelector("#workspace-select");
const workspacePath = document.querySelector("#workspace-path");
const updatedLabel = document.querySelector("#updated-label");
const viewLabel = document.querySelector("#view-label");
const drawer = document.querySelector("#detail-drawer");
const drawerContent = document.querySelector("#drawer-content");
const drawerBackdrop = document.querySelector("#drawer-backdrop");
const toast = document.querySelector("#toast");
const themeMedia = window.matchMedia("(prefers-color-scheme: dark)");

const THEME_STORAGE_KEY = "finsec-theme";
const THEME_PREFERENCES = new Set(["system", "light", "dark"]);

const state = {
  workspaces: [],
  workspaceKey: null,
  overview: null,
  cache: {},
  view: "overview",
  lastIngestResult: null,
  setupAccountIndex: 2,
  hypothesisFilters: { kind: "ALL", priority: "ALL", query: "" },
  endpointFilters: { classification: "ALL", disposition: "ALL", query: "" },
};

const VIEW_LABELS = {
  setup: "WORKSPACE SETUP",
  overview: "OVERVIEW",
  ingest: "PASSIVE INGESTION",
  authentication: "ACTOR AUTHENTICATION",
  hypotheses: "HYPOTHESES",
  endpoints: "ENDPOINTS",
  model: "INFERRED MODEL",
  evidence: "EVIDENCE & VALIDATION",
  documents: "SCOPE & NOTES",
};

document.addEventListener("DOMContentLoaded", boot);

async function boot() {
  bindGlobalEvents();
  try {
    const payload = await api("/api/workspaces");
    state.workspaces = payload.workspaces.filter((workspace) => workspace.valid);
    if (!state.workspaces.length) {
      state.workspaceKey = null;
      renderWorkspaceOptions();
      await navigate("setup", false);
      return;
    }
    const remembered = window.localStorage.getItem("finsec-workspace");
    const selected = state.workspaces.find((workspace) => workspace.key === remembered);
    state.workspaceKey = selected ? selected.key : state.workspaces[0].key;
    renderWorkspaceOptions();
    await loadOverview();
    const initialView = readHash();
    await navigate(initialView, false);
  } catch (error) {
    renderError(error);
  }
}

function bindGlobalEvents() {
  bindThemeEvents();
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => navigate(button.dataset.view));
  });
  workspaceSelect.addEventListener("change", changeWorkspace);
  document.querySelector("#refresh-button").addEventListener("click", refreshCurrentView);
  document.querySelector("#drawer-close").addEventListener("click", closeDrawer);
  drawerBackdrop.addEventListener("click", closeDrawer);
  window.addEventListener("hashchange", () => navigate(readHash(), false));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeDrawer();
  });
  content.addEventListener("click", handleContentClick);
  content.addEventListener("input", handleContentInput);
  content.addEventListener("change", handleContentInput);
  content.addEventListener("submit", handleContentSubmit);
  drawerContent.addEventListener("click", handleContentClick);
  drawerContent.addEventListener("input", handleContentInput);
  drawerContent.addEventListener("change", handleContentInput);
  drawerContent.addEventListener("submit", handleContentSubmit);
}

function bindThemeEvents() {
  const preference = document.documentElement.dataset.themePreference || "system";
  updateThemeControls(preference);
  document.querySelectorAll("[data-theme-choice]").forEach((button) => {
    button.addEventListener("click", () => setThemePreference(button.dataset.themeChoice));
  });
  themeMedia.addEventListener("change", () => {
    if (document.documentElement.dataset.themePreference === "system") {
      applyThemePreference("system");
    }
  });
}

function setThemePreference(preference) {
  if (!THEME_PREFERENCES.has(preference)) return;
  try {
    if (preference === "system") window.localStorage.removeItem(THEME_STORAGE_KEY);
    else window.localStorage.setItem(THEME_STORAGE_KEY, preference);
  } catch {
    // The selected theme still applies for this page when storage is unavailable.
  }
  applyThemePreference(preference);
}

function applyThemePreference(preference) {
  const resolvedTheme = preference === "system" ? (themeMedia.matches ? "dark" : "light") : preference;
  document.documentElement.dataset.theme = resolvedTheme;
  document.documentElement.dataset.themePreference = preference;
  updateThemeControls(preference);
}

function updateThemeControls(preference) {
  document.querySelectorAll("[data-theme-choice]").forEach((button) => {
    const isActive = button.dataset.themeChoice === preference;
    button.classList.toggle("is-active", isActive);
    button.setAttribute("aria-pressed", String(isActive));
  });
}

function readHash() {
  const candidate = window.location.hash.replace("#", "");
  return Object.hasOwn(VIEW_LABELS, candidate) ? candidate : "overview";
}

async function changeWorkspace() {
  state.workspaceKey = workspaceSelect.value;
  window.localStorage.setItem("finsec-workspace", state.workspaceKey);
  state.cache = {};
  state.overview = null;
  closeDrawer();
  setLoading("Switching research workspace...");
  try {
    await loadOverview();
    await navigate(state.view, false);
  } catch (error) {
    renderError(error);
  }
}

async function refreshCurrentView() {
  const button = document.querySelector("#refresh-button");
  button.classList.add("is-spinning");
  state.cache = {};
  try {
    await refreshWorkspaceCatalog();
    if (state.workspaceKey) await loadOverview();
    await navigate(state.view, false);
    showToast("Local workspace data refreshed.");
  } catch (error) {
    renderError(error);
  } finally {
    button.classList.remove("is-spinning");
  }
}

async function navigate(view, updateHash = true) {
  if (!Object.hasOwn(VIEW_LABELS, view)) view = "overview";
  if (!state.workspaceKey && view !== "setup") view = "setup";
  state.view = view;
  if (updateHash && window.location.hash !== `#${view}`) {
    window.location.hash = view;
    return;
  }
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.view === view);
  });
  viewLabel.textContent = VIEW_LABELS[view];
  setLoading(`Loading ${VIEW_LABELS[view].toLowerCase()}...`);
  try {
    if (view === "setup") {
      renderSetup();
      return;
    }
    if (!state.overview) await loadOverview();
    if (view === "overview") renderOverview(state.overview);
    if (view === "ingest") renderIngest(await loadView("ingest"), state.lastIngestResult);
    if (view === "authentication") renderAuthentication(await loadView("authentication"));
    if (view === "hypotheses") renderHypotheses(await loadView("hypotheses"));
    if (view === "endpoints") renderEndpoints(await loadView("endpoints"));
    if (view === "model") renderModel(await loadView("model"));
    if (view === "evidence") renderEvidence(await loadView("evidence"));
    if (view === "documents") renderDocuments(await loadView("documents"));
  } catch (error) {
    renderError(error);
  }
}

async function loadOverview() {
  state.overview = await api(workspaceApi("overview"));
  workspacePath.textContent = state.overview.workspace.path;
  workspacePath.title = state.overview.workspace.path;
  updatedLabel.textContent = state.overview.workspace.updated_at
    ? `Workspace updated ${formatDate(state.overview.workspace.updated_at)}`
    : "Workspace has no generated artifacts yet";
}

async function loadView(view) {
  if (!state.cache[view]) state.cache[view] = await api(workspaceApi(view));
  return state.cache[view];
}

function workspaceApi(path) {
  if (!state.workspaceKey) throw new Error("Select or create a workspace first.");
  return `/api/workspaces/${encodeURIComponent(state.workspaceKey)}/${path}`;
}

async function api(path, options = {}) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  const response = await fetch(path, { ...options, headers });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `Request failed with ${response.status}`);
  return payload;
}

function writeJson(path, payload) {
  return api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Finsec-UI": "1" },
    body: JSON.stringify(payload),
  });
}

function renderWorkspaceOptions() {
  if (!state.workspaces.length) {
    workspaceSelect.innerHTML = `<option value="">No workspace yet</option>`;
    workspacePath.textContent = "Create a default-deny workspace in Setup";
    return;
  }
  workspaceSelect.innerHTML = state.workspaces
    .map(
      (workspace) =>
        `<option value="${escapeHtml(workspace.key)}" ${
          workspace.key === state.workspaceKey ? "selected" : ""
        }>${escapeHtml(workspace.name)}</option>`,
    )
    .join("");
}

function renderSetup() {
  const defaultName = state.workspaces.length ? "" : "My Fintech Target";
  content.innerHTML = `
    ${pageHeading(
      "Default-deny onboarding",
      "Set up a research workspace",
      "Create the local workspace, external capture directory, explicit scope, and controlled actor labels. No credentials are collected here.",
    )}
    <form class="onboarding-form" id="setup-form">
      <section class="setup-step">
        <div class="step-index"><span>01</span><i></i></div>
        <div class="step-copy">
          <p class="eyebrow">Target identity</p>
          <h2>Name the authorized research target</h2>
          <p>The slug becomes the workspace and capture-directory name.</p>
        </div>
        <div class="form-grid">
          <label class="field field-wide">
            <span>Project display name</span>
            <input id="setup-name" name="project_name" value="${escapeAttribute(
              defaultName,
            )}" maxlength="100" required autocomplete="off">
          </label>
          <label class="field">
            <span>Workspace slug</span>
            <input id="setup-slug" name="slug" value="${escapeAttribute(
              slugify(defaultName),
            )}" maxlength="64" pattern="[a-z0-9][a-z0-9-]{0,63}" required autocomplete="off">
            <small>Lowercase letters, numbers, and hyphens.</small>
          </label>
          <label class="field">
            <span>Base URL <em>optional</em></span>
            <input name="base_url" type="url" placeholder="https://api.example.test" autocomplete="off">
            <small>Must use one of the exact scoped hosts.</small>
          </label>
          <fieldset class="mode-picker field-wide">
            <legend>Target environment</legend>
            <label class="mode-option">
              <input type="radio" name="environment" value="production" checked>
              <span><strong>Production program</strong><small>Real authorized bug bounty scope; localhost is rejected.</small></span>
            </label>
            <label class="mode-option">
              <input type="radio" name="environment" value="synthetic">
              <span><strong>Synthetic / local lab</strong><small>Allows localhost while keeping active execution disabled.</small></span>
            </label>
          </fieldset>
        </div>
      </section>

      <section class="setup-step">
        <div class="step-index"><span>02</span><i></i></div>
        <div class="step-copy">
          <p class="eyebrow">Authorized scope</p>
          <h2>Record exact host coverage</h2>
          <p>One host pattern per line. A leading wildcard does not include the apex host.</p>
        </div>
        <div class="form-grid">
          <label class="field field-wide">
            <span>In-scope hosts</span>
            <textarea name="hosts" rows="5" placeholder="example.test&#10;api.example.test&#10;*.services.example.test" required></textarea>
          </label>
          <div class="boundary-note field-wide">
            <span class="boundary-icon">!</span>
            <p><strong>Authority stays explicit.</strong> Setup creates placeholder scope and program documents. Review them against the official program rules before active testing.</p>
          </div>
        </div>
      </section>

      <section class="setup-step">
        <div class="step-index"><span>03</span><i></i></div>
        <div class="step-copy">
          <p class="eyebrow">Controlled actors</p>
          <h2>Label researcher-owned accounts</h2>
          <p>Labels are non-secret provenance. Never enter emails, tokens, cookies, or credentials.</p>
        </div>
        <div class="account-builder field-wide">
          <div class="account-list" id="setup-account-list">
            ${setupAccountRow(0, "ACCOUNT_A")}
            ${setupAccountRow(1, "ACCOUNT_B")}
          </div>
          <button class="secondary-button" type="button" data-add-account>+ Add controlled actor</button>
        </div>
      </section>

      <section class="setup-review">
        <div>
          <p class="eyebrow">Safety policy</p>
          <h2>Setup remains passive by default.</h2>
          <ul class="policy-list">
            <li>Active execution disabled</li>
            <li>Human approval required</li>
            <li>Destructive testing prohibited</li>
            <li>Maximum parallel requests: one</li>
          </ul>
        </div>
        <div class="submit-stack">
          <label class="confirm-check">
            <input id="setup-authority" type="checkbox" required>
            <span>I confirm the hosts and actor labels belong to explicitly authorized research scope.</span>
          </label>
          <button class="primary-button" type="submit">Create workspace</button>
          <p class="form-status" id="setup-status" role="status"></p>
        </div>
      </section>
    </form>
    ${renderWorkspaceDangerZone()}`;
}

function renderWorkspaceDangerZone() {
  if (!state.workspaceKey) return "";
  const workspace = state.workspaces.find((item) => item.key === state.workspaceKey);
  if (!workspace) return "";
  return `
    <section class="workspace-danger-zone">
      <div>
        <p class="eyebrow">Danger zone</p>
        <h2>Retire ${escapeHtml(workspace.name)}</h2>
        <p>Deletion is permanent. Review the exact validated paths before removing this workspace or purging all related local project data.</p>
      </div>
      <div class="danger-zone-actions">
        <button class="secondary-button" type="button" data-review-deletion="delete">Review workspace deletion</button>
        <button class="danger-button" type="button" data-review-deletion="purge">Review complete purge</button>
      </div>
    </section>`;
}

function setupAccountRow(index, accountLabel = "") {
  return `
    <div class="account-row" data-account-row="${index}">
      <label class="field">
        <span>Actor label</span>
        <input name="account_label" value="${escapeAttribute(
          accountLabel,
        )}" placeholder="ACCOUNT_A" maxlength="64" required autocomplete="off">
      </label>
      <label class="field">
        <span>Role</span>
        <input name="account_role" value="user" maxlength="100" required autocomplete="off">
      </label>
      <label class="field">
        <span>Primary channel</span>
        <select name="account_channel">
          <option value="web">Web</option>
          <option value="mobile">Mobile</option>
          <option value="api">API</option>
          <option value="unknown">Unknown</option>
        </select>
      </label>
      <label class="toggle-field">
        <input name="account_authenticated" type="checkbox" checked>
        <span>Authenticated actor</span>
      </label>
      <button class="remove-button" type="button" data-remove-account aria-label="Remove actor">x</button>
    </div>`;
}

function renderIngest(data, result = null) {
  const available = data.capture.available;
  content.innerHTML = `
    ${pageHeading(
      "Explicit capture provenance",
      "Ingest wizard",
      "Store reviewed HARs outside the workspace, assign every file to an exact actor and channel, then run the deterministic passive pipeline.",
    )}
    ${result ? renderIngestResult(result) : ""}
    <section class="ingest-path panel">
      <div>
        <p class="eyebrow">External capture directory</p>
        <h2>${escapeHtml(data.capture.incoming)}</h2>
        <p>Original captures stay outside the workspace and are excluded from Git.</p>
      </div>
      <span class="pill ${available ? "active" : "missing"}">${available ? "Ready" : "Not initialized"}</span>
    </section>
    ${
      available
        ? renderCaptureUpload(data) + renderCaptureAssignments(data)
        : `<section class="panel initialization-panel">
            <p class="eyebrow">Capture layout missing</p>
            <h2>Initialize the external input directory</h2>
            <p>This creates <code>incoming/</code> and an empty <code>workflow.yaml</code>. It does not contact the target.</p>
            <button class="primary-button" type="button" data-initialize-capture>Initialize capture directory</button>
          </section>`
    }`;
}

function renderCaptureUpload(data) {
  return `
    <section class="panel upload-panel">
      <div class="panel-heading">
        <div><h2>Add reviewed HAR files</h2><p>Maximum ${escapeHtml(
          formatBytes(data.capture.maximum_upload_bytes),
        )} per file; existing files are never overwritten.</p></div>
      </div>
      <label class="upload-zone" for="har-upload-input">
        <input id="har-upload-input" type="file" accept=".har,application/json" multiple>
        <span class="upload-glyph">HAR</span>
        <strong>Choose sanitized captures</strong>
        <small id="upload-selection">No files selected</small>
      </label>
      <div class="upload-actions">
        <label class="confirm-check">
          <input id="upload-reviewed" type="checkbox">
          <span>I reviewed these files for authorization, unrelated personal data, and capture scope.</span>
        </label>
        <button class="secondary-button" type="button" data-upload-hars>Upload selected HARs</button>
      </div>
      <p class="form-status" id="upload-status" role="status"></p>
    </section>`;
}

function renderCaptureAssignments(data) {
  if (!data.files.length) {
    return `<section class="panel no-captures"><p class="eyebrow">Waiting for captures</p><h2>No HAR files are available yet.</h2><p>Add reviewed files with the upload area or place them directly in <code>${escapeHtml(
      data.capture.incoming,
    )}</code>, then refresh.</p></section>`;
  }
  const hasSavedAssignments = data.files.some((file) => file.assigned);
  return `
    <form class="panel assignment-panel" id="ingest-form">
      <div class="panel-heading">
        <div><h2>Assign actor and channel</h2><p>Filenames never determine provenance. Every enabled file requires an explicit selection.</p></div>
        <span class="pill">${formatNumber(data.files.length)} files</span>
      </div>
      ${
        data.missing_manifest_files.length
          ? `<div class="boundary-note"><span class="boundary-icon">!</span><p>Manifest entries reference missing files: ${escapeHtml(
              data.missing_manifest_files.join(", "),
            )}</p></div>`
          : ""
      }
      <div class="assignment-list">
        ${data.files.map((file) => captureAssignmentRow(file, data)).join("")}
      </div>
      <div class="ingest-controls">
        <div>
          <label class="confirm-check">
            <input name="reviewed" type="checkbox" required>
            <span>I confirm each enabled file is authorized, sanitized, and assigned to the correct actor and channel.</span>
          </label>
          <label class="confirm-check">
            <input name="run_analysis" type="checkbox" checked>
            <span>Run inventory, modeling, invariants, and hypothesis generation after ingestion.</span>
          </label>
        </div>
        <div class="ingest-actions">
          <button class="${hasSavedAssignments ? "secondary-button" : "primary-button"}" type="submit">Ingest selected captures</button>
          ${
            hasSavedAssignments
              ? `<button class="primary-button" type="button" data-rerun-workflow>Run passive workflow again</button>`
              : ""
          }
        </div>
      </div>
      <p class="form-status" id="ingest-status" role="status"></p>
    </form>`;
}

function captureAssignmentRow(file, data) {
  return `
    <div class="capture-row" data-capture-file="${escapeAttribute(file.file)}">
      <label class="capture-enabled">
        <input name="capture_enabled" type="checkbox" ${file.enabled ? "checked" : ""}>
        <span class="sr-only">Enable ${escapeHtml(file.file)}</span>
      </label>
      <div class="capture-file">
        <span class="record-id">${escapeHtml(file.file)}</span>
        <small>${escapeHtml(formatBytes(file.size))} / ${file.assigned ? "assigned" : "new"}</small>
      </div>
      <label class="field compact-field">
        <span>Actor</span>
        <select name="capture_actor">
          <option value="">Choose actor</option>
          ${data.actors
            .map(
              (actor) =>
                `<option value="${escapeAttribute(actor.id)}" ${
                  file.actor === actor.id ? "selected" : ""
                }>${escapeHtml(actor.id)} / ${escapeHtml(actor.role)}</option>`,
            )
            .join("")}
          ${data.special_actors
            .map(
              (actor) =>
                `<option value="${escapeAttribute(actor)}" ${
                  file.actor === actor ? "selected" : ""
                }>${escapeHtml(actor)}</option>`,
            )
            .join("")}
        </select>
      </label>
      <label class="field compact-field">
        <span>Channel</span>
        <select name="capture_channel">
          <option value="">Choose channel</option>
          ${data.channels
            .map(
              (channel) =>
                `<option value="${escapeAttribute(channel)}" ${
                  file.channel === channel ? "selected" : ""
                }>${escapeHtml(label(channel))}</option>`,
            )
            .join("")}
        </select>
      </label>
    </div>`;
}

function renderIngestResult(result) {
  const imported = result.ingested.reduce((total, item) => total + item.imported, 0);
  const relabeled = result.ingested.reduce((total, item) => total + item.relabeled, 0);
  return `
    <section class="operation-result">
      <div><p class="eyebrow">Passive workflow complete</p><h2>${formatNumber(
        imported,
      )} observations imported</h2><p>${formatNumber(relabeled)} provenance labels refreshed; ${formatNumber(
        result.network_requests_sent,
      )} target requests sent.</p></div>
      ${
        result.analysis
          ? `<div class="result-metrics"><span><strong>${formatNumber(
              result.analysis.endpoints,
            )}</strong> endpoints</span><span><strong>${formatNumber(
              result.analysis.active_hypotheses,
            )}</strong> hypotheses</span><span><strong>${formatNumber(
              result.analysis.research_tasks,
            )}</strong> research tasks</span></div>`
          : `<span class="pill active">Ingestion only</span>`
      }
    </section>`;
}

function renderAuthentication(data) {
  const ready = data.actors.filter((actor) =>
    ["READY", "NONE"].includes(actor.preflight.status),
  ).length;
  const blocked = data.actors.filter(
    (actor) => actor.preflight.result === "BLOCKED_BY_AUTH",
  ).length;
  const refreshable = data.actors.filter((actor) => actor.preflight.refresh_available).length;
  content.innerHTML = `
    ${pageHeading(
      "Actor-bound readiness",
      "Authentication control room",
      "Inspect local credential availability, expiration, refresh capability, and identity continuity without returning secret material or contacting the target.",
    )}
    <section class="view-summary-grid">
      ${summaryCard("Configured actors", data.actors.length)}
      ${summaryCard("Locally ready", ready)}
      ${summaryCard("Blocked", blocked)}
      ${summaryCard("Refresh flows", refreshable)}
    </section>
    <section class="auth-safety-panel">
      <div>
        <p class="eyebrow">Zero-request preflight</p>
        <h2>The browser checks readiness, never credentials.</h2>
        <p>Secret values and credential references remain in the permission-restricted local store. Configuration and live validation stay in the secure CLI.</p>
      </div>
      <div class="auth-safety-facts">
        <span><strong>${formatNumber(data.network_requests_sent)}</strong> target requests</span>
        <span><strong>${escapeHtml(data.storage.permissions || "Not created")}</strong> store mode</span>
        <span><strong>${formatDate(data.checked_at)}</strong> checked</span>
      </div>
    </section>
    <section class="auth-grid">
      ${
        data.actors.length
          ? data.actors.map((actor) => renderAuthenticationCard(actor, data)).join("")
          : renderInlineEmpty("No controlled actors are configured in this workspace.")
      }
    </section>
    <section class="panel auth-cli-boundary">
      <div>
        <p class="eyebrow">Secure handoff</p>
        <h2>Credential-changing steps remain CLI-only</h2>
        <p>The terminal uses hidden input or reviewed local files and keeps credential-bearing material out of browser state, history, and responses.</p>
      </div>
      ${authCommand(
        "List every actor",
        `hunt actors --workspace ${shellQuote(data.workspace.path)}`,
      )}
    </section>`;
}

function renderAuthenticationCard(actor, data) {
  const preflight = actor.preflight;
  const anonymous = actor.actor_type === "anonymous" || !actor.authenticated;
  const statusClass = authenticationStatusClass(preflight.status);
  const resultLabel =
    preflight.result === "BLOCKED_BY_AUTH"
      ? "Blocked by authentication"
      : preflight.result === "READY_FOR_EXECUTION"
        ? "Locally ready"
        : "Ready for planning";
  return `
    <article class="panel auth-card">
      <div class="auth-card-top">
        <div>
          <span class="record-id">${escapeHtml(actor.id)}</span>
          <h2>${escapeHtml(actor.role)}</h2>
          <p>${escapeHtml(label(actor.actor_type))}</p>
        </div>
        ${pill(preflight.status, statusClass)}
      </div>
      <div class="auth-result ${preflight.result === "BLOCKED_BY_AUTH" ? "is-blocked" : "is-ready"}">
        <span>Local preflight</span>
        <strong>${escapeHtml(resultLabel)}</strong>
      </div>
      <div class="auth-facts">
        ${authFact("Credential available", preflight.credential_available ? "Yes" : "No")}
        ${authFact("Authentication type", actor.auth_type ? label(actor.auth_type) : "Not configured")}
        ${authFact("Expires", preflight.expires_at ? formatDate(preflight.expires_at) : "Unknown")}
        ${authFact("Remaining lifetime", formatRemaining(preflight.remaining_seconds))}
        ${authFact("Observed refresh", preflight.refresh_available ? "Configured" : "Not configured")}
        ${authFact("Target validated", preflight.target_validated ? "Recorded" : "Not recorded")}
        ${authFact(
          "Last target validation",
          actor.last_validated_at ? formatDate(actor.last_validated_at) : "Never",
        )}
        ${authFact(
          "Baseline identity",
          preflight.baseline_identity_confirmed ? "Confirmed" : "Not confirmed",
        )}
        ${authFact("Source", actor.source ? label(actor.source) : "Not configured")}
      </div>
      ${
        preflight.reasons.length
          ? `<div class="auth-reasons"><strong>Preflight blockers</strong>${renderSimpleList(
              preflight.reasons,
              "detail-list",
            )}</div>`
          : ""
      }
      <div class="auth-card-actions">
        <button class="secondary-button" type="button" data-auth-check="${escapeAttribute(
          actor.id,
        )}">Check locally again</button>
        <span>${formatNumber(data.network_requests_sent)} requests sent</span>
      </div>
      ${anonymous ? renderAnonymousAuthentication() : renderAuthenticationCommands(actor, data)}
    </article>`;
}

function renderAnonymousAuthentication() {
  return `<div class="auth-none"><strong>No credential required</strong><p>This actor is explicitly anonymous and is locally ready without a secret profile.</p></div>`;
}

function renderAuthenticationCommands(actor, data) {
  const actorArg = shellQuote(actor.id);
  const workspaceArg = shellQuote(data.workspace.path);
  return `
    <details class="auth-commands">
      <summary>Secure CLI authentication steps</summary>
      <div class="auth-command-list">
        ${authCommand(
          "Inspect status",
          `hunt actor auth status ${actorArg} --workspace ${workspaceArg}`,
        )}
        ${authCommand(
          "Set with hidden prompt",
          `hunt actor auth set ${actorArg} --workspace ${workspaceArg}`,
        )}
        ${authCommand(
          "Import reviewed request",
          `hunt actor auth import ${actorArg} --request '/path/to/reviewed-request.txt' --workspace ${workspaceArg}`,
        )}
        ${authCommand(
          "Refresh from HAR",
          `hunt actor auth refresh ${actorArg} --har '/path/to/fresh-auth.har' --workspace ${workspaceArg}`,
        )}
        ${authCommand(
          "Refresh from Burp",
          `hunt actor auth refresh ${actorArg} --burp '/path/to/fresh-auth.xml' --workspace ${workspaceArg}`,
        )}
        ${authCommand(
          "Refresh from request",
          `hunt actor auth refresh ${actorArg} --request '/path/to/fresh-request.txt' --workspace ${workspaceArg}`,
        )}
        ${authCommand(
          "Configure refresh flow",
          `hunt actor auth configure-refresh ${actorArg} --har '/path/to/refresh-flow.har' --workspace ${workspaceArg}`,
        )}
        ${authCommand(
          "Run configured refresh",
          `hunt actor auth refresh ${actorArg} --workspace ${workspaceArg}`,
          "Sends the bounded observed refresh request configured for this actor",
        )}
        ${authCommand(
          "One-request target check",
          `hunt actor auth check ${actorArg} --network --workspace ${workspaceArg}`,
          "Sends one explicitly confirmed read-only baseline request",
        )}
        ${authCommand(
          "Clear authentication",
          `hunt actor auth clear ${actorArg} --workspace ${workspaceArg}`,
          "Removes this actor's stored credentials and invalidates affected approvals",
        )}
      </div>
    </details>`;
}

function authCommand(title, command, warning = "") {
  return `
    <div class="auth-command ${warning ? "is-warning" : ""}">
      <div><strong>${escapeHtml(title)}</strong>${
        warning ? `<span>${escapeHtml(warning)}</span>` : ""
      }</div>
      <code>${escapeHtml(command)}</code>
      <button class="copy-button" type="button" data-copy="${escapeAttribute(command)}">Copy</button>
    </div>`;
}

function authFact(title, value) {
  return `<div class="auth-fact"><span>${escapeHtml(title)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function authenticationStatusClass(status) {
  if (["READY", "NONE"].includes(status)) return "active";
  if (["EXPIRING_SOON", "REFRESH_REQUIRED"].includes(status)) return "missing";
  return "blocked";
}

function renderOverview(data) {
  const counts = data.counts;
  const hostCopy = data.scope.hosts.length
    ? data.scope.hosts.join(", ")
    : "Scope hosts have not been configured";
  content.innerHTML = `
    <section class="hero">
      <div>
        <p class="eyebrow">Authorized research cockpit</p>
        <h1>${escapeHtml(data.workspace.name)}</h1>
        <p class="hero-subtitle">${escapeHtml(hostCopy)}</p>
      </div>
      <div class="hero-meta">
        <div class="hero-meta-item">
          <span>Research mode</span>
          <strong>${data.testing.production ? "Production target" : "Synthetic / non-production"}</strong>
        </div>
        <div class="hero-meta-item">
          <span>Active execution</span>
          <strong>${data.testing.active_execution_enabled ? "Enabled by target policy" : "Disabled"}</strong>
        </div>
        <div class="hero-meta-item">
          <span>Controlled actors</span>
          <strong>${formatNumber(data.accounts.length)}</strong>
        </div>
        <div class="hero-meta-item">
          <span>Knowledge state</span>
          <strong>${counts.reports ? "Reported findings exist" : "Research in progress"}</strong>
        </div>
      </div>
    </section>

    <section class="stats-grid" aria-label="Workspace totals">
      ${statCard("01", counts.observations, "Observations")}
      ${statCard("02", counts.endpoints, "Endpoint families")}
      ${statCard("03", counts.active_hypotheses, "Active hypotheses", true)}
      ${statCard("04", counts.evidence_sets, "Evidence sets")}
      ${statCard("05", counts.validations, "Validations")}
      ${statCard("06", counts.reports, "Reports")}
    </section>

    <section class="workflow-panel">
      <div class="panel-heading">
        <div>
          <h2>Research pipeline</h2>
          <p>Knowledge moves forward only when the prior evidence contract exists.</p>
        </div>
        <button class="text-button" type="button" data-view-link="documents">Review scope</button>
      </div>
      <div class="pipeline">
        ${data.stages
          .map(
            (stage) => `
              <div class="pipeline-stage ${escapeHtml(stage.state)}">
                <span class="pipeline-dot"></span>
                <strong>${escapeHtml(stage.label)}</strong>
                <span>${formatNumber(stage.count)} records</span>
              </div>`,
          )
          .join("")}
      </div>
    </section>

    <section class="dashboard-grid">
      <article class="panel next-action">
        <p class="eyebrow">${escapeHtml(data.next_action.eyebrow)}</p>
        <h2>${escapeHtml(data.next_action.title)}</h2>
        <p>${escapeHtml(data.next_action.description)}</p>
        ${
          data.next_action.command
            ? `<div class="command-row">
                <code>${escapeHtml(data.next_action.command)}</code>
                <button class="copy-button" type="button" data-copy="${escapeAttribute(
                  data.next_action.command,
                )}">COPY</button>
              </div>`
            : `<p class="eyebrow">Manual review required</p>`
        }
      </article>
      <article class="panel">
        <div class="panel-heading">
          <div>
            <h3>Authorized scope</h3>
            <p>${formatNumber(data.scope.hosts.length)} configured host patterns</p>
          </div>
        </div>
        ${renderSimpleList(data.scope.hosts, "scope-list", true)}
      </article>
    </section>

    <section class="panel table-panel">
      <div class="panel-heading">
        <div>
          <h2>Highest-priority research queue</h2>
          <p>Priority is queue position, not vulnerability severity.</p>
        </div>
        <button class="text-button" type="button" data-view-link="hypotheses">Open backlog</button>
      </div>
      ${renderHypothesisTable(data.highest_priority)}
    </section>

    <section class="dashboard-grid section-spaced">
      <article class="panel">
        <div class="panel-heading">
          <div>
            <h3>Passive coverage</h3>
            <p>Provenance distribution across supplied observations.</p>
          </div>
        </div>
        ${renderCoverage(data.coverage.channels)}
      </article>
      <article class="panel">
        <div class="panel-heading">
          <div>
            <h3>Knowledge contract</h3>
            <p>The dashboard keeps these states distinct.</p>
          </div>
        </div>
        <ul class="legend-list">
          ${data.knowledge_legend
            .map(
              (item) =>
                `<li><span class="pill ${slug(item.state)}">${escapeHtml(item.state)}</span><span>${escapeHtml(
                  item.description,
                )}</span></li>`,
            )
            .join("")}
        </ul>
      </article>
    </section>`;
}

function renderHypotheses(data) {
  const hypotheses = data.hypotheses;
  const active = hypotheses.filter(
    (item) => item.kind === "SECURITY_HYPOTHESIS" && item.disposition === "ACTIVE",
  );
  const tasks = hypotheses.filter((item) => item.kind === "RESEARCH_TASK");
  const planned = hypotheses.filter((item) => item.plan_status).length;
  const evidenced = hypotheses.filter((item) => item.evidence_artifacts > 0).length;
  content.innerHTML = `
    ${pageHeading(
      "Evidence-gated backlog",
      "Hypotheses",
      "Specific research questions, transparent scores, and the evidence gaps that prevent premature findings.",
    )}
    <section class="view-summary-grid">
      ${summaryCard("Active hypotheses", active.length)}
      ${summaryCard("Research tasks", tasks.length)}
      ${summaryCard("Plans generated", planned)}
      ${summaryCard("With evidence", evidenced)}
    </section>
    <div class="toolbar">
      ${searchField("hypothesis-search", "Search title, component, or ID", state.hypothesisFilters.query)}
      ${filterSelect(
        "hypothesis-kind",
        [
          ["ALL", "All records"],
          ["SECURITY_HYPOTHESIS", "Hypotheses"],
          ["RESEARCH_TASK", "Research tasks"],
        ],
        state.hypothesisFilters.kind,
      )}
      ${filterSelect(
        "hypothesis-priority",
        [
          ["ALL", "All priorities"],
          ["P1", "P1 queue"],
          ["P2", "P2 queue"],
          ["P3", "P3 queue"],
        ],
        state.hypothesisFilters.priority,
      )}
    </div>
    <section class="panel table-panel" id="hypothesis-results">
      ${renderHypothesisTable(filteredHypotheses(hypotheses), true)}
    </section>`;
}

function renderHypothesisTable(hypotheses, includeLifecycle = false) {
  if (!hypotheses.length) return renderInlineEmpty("No backlog records match these filters.");
  return `
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>ID</th><th>Queue</th><th>Research question</th><th>Category</th><th>Score</th>
            ${includeLifecycle ? "<th>Lifecycle</th>" : "<th>Status</th>"}
          </tr>
        </thead>
        <tbody>
          ${hypotheses
            .map(
              (item) => `
                <tr data-record="hypothesis" data-id="${escapeAttribute(item.id)}" tabindex="0">
                  <td><span class="record-id">${escapeHtml(item.id)}</span></td>
                  <td>${pill(item.priority)}</td>
                  <td class="title-cell">${escapeHtml(item.title)}</td>
                  <td>${pill(item.kind === "RESEARCH_TASK" ? "Research task" : item.category)}</td>
                  <td class="mono">${formatNumber(item.score)}/20</td>
                  <td>${pill(
                    includeLifecycle
                      ? item.validation_disposition || item.plan_status || item.status
                      : item.status,
                  )}</td>
                </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>`;
}

function filteredHypotheses(hypotheses) {
  const query = state.hypothesisFilters.query.toLowerCase().trim();
  return hypotheses.filter((item) => {
    const kindMatches =
      state.hypothesisFilters.kind === "ALL" || item.kind === state.hypothesisFilters.kind;
    const priorityMatches =
      state.hypothesisFilters.priority === "ALL" ||
      item.priority === state.hypothesisFilters.priority;
    const queryMatches =
      !query ||
      [item.id, item.title, item.component, item.category].join(" ").toLowerCase().includes(query);
    return kindMatches && priorityMatches && queryMatches;
  });
}

function updateHypothesisResults() {
  const target = document.querySelector("#hypothesis-results");
  if (!target || !state.cache.hypotheses) return;
  target.innerHTML = renderHypothesisTable(
    filteredHypotheses(state.cache.hypotheses.hypotheses),
    true,
  );
}

function renderEndpoints(data) {
  const active = data.endpoints.filter((item) => item.disposition === "ACTIVE");
  const stateChanging = active.filter((item) => item.state_change).length;
  const authRequired = active.filter((item) => item.authentication.required).length;
  content.innerHTML = `
    ${pageHeading(
      "Normalized inventory",
      "Endpoint explorer",
      "Conservative route families derived from passive observations. Concrete request values remain outside this interface.",
    )}
    <section class="view-summary-grid">
      ${summaryCard("Endpoint families", data.endpoints.length)}
      ${summaryCard("Active", active.length)}
      ${summaryCard("State changing", stateChanging)}
      ${summaryCard("Auth inferred", authRequired)}
    </section>
    <div class="toolbar">
      ${searchField("endpoint-search", "Search method, path, resource, or ID", state.endpointFilters.query)}
      ${filterSelect(
        "endpoint-classification",
        [["ALL", "All classifications"]].concat(
          data.classifications.map((item) => [item.label, label(item.label)]),
        ),
        state.endpointFilters.classification,
      )}
      ${filterSelect(
        "endpoint-disposition",
        [["ALL", "All dispositions"]].concat(
          data.dispositions.map((item) => [item.label, label(item.label)]),
        ),
        state.endpointFilters.disposition,
      )}
    </div>
    <section class="panel table-panel" id="endpoint-results">
      ${renderEndpointTable(filteredEndpoints(data.endpoints))}
    </section>`;
}

function renderEndpointTable(endpoints) {
  if (!endpoints.length) return renderInlineEmpty("No endpoint families match these filters.");
  return `
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr><th>ID</th><th>Method</th><th>Normalized path</th><th>Resource</th><th>Class</th><th>Relevance</th></tr>
        </thead>
        <tbody>
          ${endpoints
            .map(
              (item) => `
                <tr data-record="endpoint" data-id="${escapeAttribute(item.id)}" tabindex="0">
                  <td><span class="record-id">${escapeHtml(item.id)}</span></td>
                  <td><span class="method ${slug(item.method)}">${escapeHtml(item.method)}</span></td>
                  <td class="title-cell mono">${escapeHtml(item.path)}</td>
                  <td>${escapeHtml(item.resource.type)}</td>
                  <td>${pill(item.classification.primary)}</td>
                  <td><span class="record-id">${formatNumber(item.security_relevance)}/10</span></td>
                </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>`;
}

function filteredEndpoints(endpoints) {
  const query = state.endpointFilters.query.toLowerCase().trim();
  return endpoints.filter((item) => {
    const classificationMatches =
      state.endpointFilters.classification === "ALL" ||
      item.classification.primary === state.endpointFilters.classification;
    const dispositionMatches =
      state.endpointFilters.disposition === "ALL" ||
      item.disposition === state.endpointFilters.disposition;
    const queryMatches =
      !query ||
      [item.id, item.method, item.path, item.resource.type, item.action.name]
        .join(" ")
        .toLowerCase()
        .includes(query);
    return classificationMatches && dispositionMatches && queryMatches;
  });
}

function updateEndpointResults() {
  const target = document.querySelector("#endpoint-results");
  if (!target || !state.cache.endpoints) return;
  target.innerHTML = renderEndpointTable(filteredEndpoints(state.cache.endpoints.endpoints));
}

function renderModel(data) {
  const activeResources = data.resources.filter((item) => item.disposition === "ACTIVE");
  const activeInvariants = data.invariants.filter((item) => item.disposition === "ACTIVE");
  content.innerHTML = `
    ${pageHeading(
      "Derived architecture",
      "Inferred model",
      "Actors and resources are conservative inferences. Invariants are expected properties, not proof of enforcement.",
    )}
    <section class="model-section">
      <div class="section-title"><h2>Actors</h2><p>${formatNumber(data.actors.length)} configured or inferred labels</p></div>
      <div class="record-grid">
        ${data.actors.length ? data.actors.map(renderActorCard).join("") : renderInlineEmpty("No actors have been modeled yet.")}
      </div>
    </section>
    <section class="model-section">
      <div class="section-title"><h2>Business resources</h2><p>${formatNumber(activeResources.length)} active inferred resources</p></div>
      <div class="record-grid">
        ${activeResources.length ? activeResources.map(renderResourceCard).join("") : renderInlineEmpty("No resources have been modeled yet.")}
      </div>
    </section>
    <section class="model-section">
      <div class="section-title"><h2>Expected invariants</h2><p>${formatNumber(activeInvariants.length)} properties awaiting confirmation</p></div>
      <div class="invariant-list">
        ${activeInvariants.length ? activeInvariants.map(renderInvariantRow).join("") : renderInlineEmpty("No invariants have been generated yet.")}
      </div>
    </section>`;
}

function renderActorCard(actor) {
  return `
    <article class="record-card">
      <div class="record-card-top">
        <div><span class="record-id">${escapeHtml(actor.id)}</span><h3>${escapeHtml(actor.name)}</h3></div>
        ${pill(actor.knowledge_status)}
      </div>
      <p>Role: ${escapeHtml(actor.role?.value || "Not confirmed")}<br>Ownership: ${escapeHtml(
        actor.ownership?.value || "Not confirmed",
      )}</p>
      <div class="record-meta">
        ${pill(actor.confidence)}
        ${(actor.authentication_types || []).map((item) => pill(item)).join("")}
      </div>
    </article>`;
}

function renderResourceCard(resource) {
  return `
    <article class="record-card">
      <div class="record-card-top">
        <div><span class="record-id">${escapeHtml(resource.id)}</span><h3>${escapeHtml(resource.name)}</h3></div>
        ${pill(resource.confidence)}
      </div>
      <p>${formatNumber(resource.operations.length)} inferred operations; ${formatNumber(
        resource.identifiers.length,
      )} identifiers; owner ${escapeHtml(resource.owner?.value || "not confirmed")}.</p>
      <div class="record-meta">
        ${resource.operations.slice(0, 3).map((operation) => pill(operation.method)).join("")}
        ${resource.operations.length > 3 ? pill(`+${resource.operations.length - 3} more`) : ""}
      </div>
    </article>`;
}

function renderInvariantRow(invariant) {
  return `
    <article class="invariant-row">
      <span class="record-id">${escapeHtml(invariant.id)}</span>
      <div><h3>${escapeHtml(invariant.statement)}</h3><p>${escapeHtml(label(invariant.category))} / ${formatNumber(
        invariant.endpoints.length,
      )} endpoints / ${formatNumber(invariant.evidence.length)} evidence links</p></div>
      ${pill(invariant.validation_status)}
    </article>`;
}

function renderEvidence(data) {
  const validations = [
    ...data.evidence_sets.map((item) => item.validation).filter(Boolean),
    ...data.validations_without_evidence.filter(Boolean),
  ];
  const confirmed = validations.filter((item) => item.disposition === "CONFIRMED").length;
  const needsEvidence = validations.filter(
    (item) => item.disposition === "NEEDS_MORE_EVIDENCE",
  ).length;
  content.innerHTML = `
    ${pageHeading(
      "Skeptical validation",
      "Evidence chain",
      "Indexed redacted artifacts, explicit researcher assessments, and validation outcomes. File contents stay outside browser responses.",
    )}
    <section class="view-summary-grid">
      ${summaryCard("Evidence sets", data.evidence_sets.length)}
      ${summaryCard("Validation records", validations.length)}
      ${summaryCard("Needs evidence", needsEvidence)}
      ${summaryCard("Confirmed", confirmed)}
    </section>
    <section class="model-section">
      <div class="section-title"><h2>Evidence packages</h2><p>Metadata and integrity state only</p></div>
      <div class="evidence-list">
        ${
          data.evidence_sets.length
            ? data.evidence_sets.map(renderEvidenceRow).join("")
            : renderInlineEmpty("No evidence sets have been scaffolded yet.")
        }
      </div>
    </section>
    <section class="model-section">
      <div class="section-title"><h2>Immutable reports</h2><p>${formatNumber(data.reports.length)} local revisions</p></div>
      <div class="record-grid">
        ${
          data.reports.length
            ? data.reports
                .map(
                  (report) => `
                    <article class="record-card">
                      <span class="record-id">REPORT REVISION</span>
                      <h3>${escapeHtml(report)}</h3>
                      <p>Generated from a confirmed, report-ready local validation contract.</p>
                      <div class="record-meta"><button class="text-button" type="button" data-report="${escapeAttribute(
                        report,
                      )}">Read report</button></div>
                    </article>`,
                )
                .join("")
            : renderInlineEmpty("No report revisions exist yet.")
        }
      </div>
    </section>`;
}

function renderEvidenceRow(item) {
  const metadata = item.metadata;
  const validation = item.validation;
  return `
    <article class="evidence-row" data-record="hypothesis" data-id="${escapeAttribute(
      metadata.hypothesis_id,
    )}" tabindex="0">
      <span class="record-id">${escapeHtml(metadata.hypothesis_id)}</span>
      <div>
        <h3>${formatNumber(metadata.artifacts.length)} indexed redacted artifacts</h3>
        <p>${validation ? escapeHtml(validation.summary) : "Not validated yet."}</p>
      </div>
      ${pill(validation?.disposition || "NOT VALIDATED")}
    </article>`;
}

function renderDocuments(data) {
  const firstExisting = data.documents.find((document) => document.exists) || data.documents[0];
  content.innerHTML = `
    ${pageHeading(
      "Research boundary",
      "Scope & notes",
      "Allowlisted workspace documents that define authorization, restrictions, architecture, and researcher context.",
    )}
    <section class="document-layout">
      <nav class="document-nav" aria-label="Workspace documents">
        ${data.documents
          .map(
            (document) => `
              <button class="document-tab ${document.id === firstExisting?.id ? "is-active" : ""}" type="button" data-document="${escapeAttribute(
                document.id,
              )}">
                <span>${escapeHtml(document.title)}</span>
                <small>${document.exists ? "Available" : "Not generated"}</small>
              </button>`,
          )
          .join("")}
      </nav>
      <article class="document-panel" id="document-panel">
        <div class="loading-state compact-loading"><p>Loading document...</p></div>
      </article>
    </section>`;
  if (firstExisting) loadDocument(firstExisting.id);
}

async function loadDocument(documentId) {
  const panel = document.querySelector("#document-panel");
  if (!panel) return;
  panel.innerHTML = `<div class="loading-state compact-loading"><p>Loading document...</p></div>`;
  document.querySelectorAll("[data-document]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.document === documentId);
  });
  try {
    const documentData = await api(workspaceApi(`documents/${encodeURIComponent(documentId)}`));
    panel.innerHTML = documentData.exists
      ? `<div class="markdown-body">${markdownToHtml(documentData.content)}</div>`
      : renderInlineEmpty(`${documentData.title} has not been generated yet.`);
  } catch (error) {
    panel.innerHTML = `<div class="error-state"><p>${escapeHtml(error.message)}</p></div>`;
  }
}

async function openHypothesis(hypothesisId) {
  openDrawer(`<div class="loading-state"><p>Tracing evidence chain...</p></div>`);
  try {
    const data = await api(workspaceApi(`hypotheses/${encodeURIComponent(hypothesisId)}`));
    drawerContent.innerHTML = renderHypothesisDrawer(data);
  } catch (error) {
    drawerContent.innerHTML = `<div class="error-state"><p>${escapeHtml(error.message)}</p></div>`;
  }
}

function renderHypothesisDrawer(data) {
  const item = data.hypothesis;
  const explanation = data.explanation || {};
  const mutation = explanation.mutation_target || {};
  const semantics = explanation.identifier_semantics || {};
  const readiness = explanation.readiness || {};
  const presentation = explanation.presentation || {};
  const plan = data.plan;
  const validation = data.validation;
  const evidence = data.evidence;
  return `
    <header class="drawer-header">
      <p class="eyebrow">${escapeHtml(item.id)} / ${escapeHtml(label(item.kind))}</p>
      <h2>${escapeHtml(item.title)}</h2>
      <div class="drawer-tags">
        ${pill(item.priority)} ${pill(item.category)} ${pill(item.status)} ${pill(item.evidence_status)}
      </div>
    </header>
    <section class="drawer-section">
      <h3>Transparent score</h3>
      <div class="score-grid">
        ${scoreCell("Impact", item.scores.impact)}
        ${scoreCell("Likelihood", item.scores.likelihood)}
        ${scoreCell("Confidence", item.scores.confidence)}
        ${scoreCell("Testability", item.scores.testability)}
      </div>
    </section>
    ${drawerTextSection("Hypothesis", item.hypothesis)}
    ${drawerTextSection("Reasoning", item.reasoning)}
    <section class="drawer-section">
      <h3>Object semantics and ownership</h3>
      <div class="check-grid">
        ${scoreCell("Mutation target", mutation.parameter || "None")}
        ${scoreCell("Semantic class", semantics.semantic_class || "OPAQUE_UNKNOWN")}
        ${scoreCell("Resource role", semantics.resource_role || "UNKNOWN")}
        ${scoreCell("Ownership", semantics.ownership_state || "UNKNOWN")}
        ${scoreCell("Cluster", presentation.cluster_id || "None")}
        ${scoreCell("Campaign", presentation.campaign_id || "None")}
      </div>
      <p class="spaced-copy">${escapeHtml(semantics.explanation || "Identifier semantics are not established.")}</p>
      ${drawerListSection("Ownership evidence", semantics.evidence || [])}
      ${drawerListSection("Counterevidence", semantics.counterevidence || [])}
    </section>
    ${drawerListSection("Readiness reasons", readiness.reasons || [])}
    ${drawerListSection("Missing readiness prerequisites", readiness.missing_prerequisites || [])}
    ${drawerListSection("Why retained", presentation.retention_reasons || [])}
    ${drawerListSection("Why distinct", presentation.difference_reasons || [])}
    ${drawerListSection("Eligibility evidence", item.eligibility_evidence)}
    ${drawerListSection("Missing evidence", item.missing_evidence)}
    ${drawerTextSection("Expected secure behavior", item.expected_secure_behavior)}
    ${drawerTextSection("Possible behavior to investigate", item.possible_vulnerable_behavior)}
    ${drawerListSection("Safety boundary", item.safety_notes, true)}
    <section class="drawer-section">
      <h3>Evidence chain</h3>
      <div class="check-grid">
        ${scoreCell("Endpoints", data.source_endpoints.length)}
        ${scoreCell("Invariants", data.source_invariants.length)}
        ${scoreCell("Artifacts", evidence?.artifacts?.length || 0)}
        ${scoreCell("Reports", data.reports.length)}
      </div>
    </section>
    ${renderPlanSection(plan)}
    ${renderValidationSection(validation)}
    ${renderSourceEndpoints(data.source_endpoints)}
  `;
}

function renderPlanSection(plan) {
  if (!plan) {
    return `<section class="drawer-section"><h3>Test plan</h3><p>No plan has been generated for this hypothesis.</p></section>`;
  }
  return `
    <section class="drawer-section">
      <h3>Test plan / ${escapeHtml(plan.id)}</h3>
      <div class="drawer-tags">${pill(plan.status)} ${pill(plan.approval_status)} ${pill(
        plan.execution.pattern,
      )}</div>
      <p class="spaced-copy">${escapeHtml(plan.purpose)}</p>
      <div class="safety-note spaced-note">Execution default: ${escapeHtml(
        plan.execution_default,
      )}. This interface cannot approve or execute a plan.</div>
      ${
        plan.execution.blockers?.length
          ? `<h3 class="subsection-title">Execution blockers</h3>${renderSimpleList(
              plan.execution.blockers,
              "detail-list",
            )}`
          : ""
      }
    </section>`;
}

function renderValidationSection(validation) {
  if (!validation) {
    return `<section class="drawer-section"><h3>Validation</h3><p>No skeptical validation record exists yet.</p></section>`;
  }
  const counts = validation.checks.reduce(
    (summary, check) => {
      summary[check.result] = (summary[check.result] || 0) + 1;
      return summary;
    },
    {},
  );
  return `
    <section class="drawer-section">
      <h3>Validation / ${escapeHtml(validation.disposition)}</h3>
      <p>${escapeHtml(validation.summary)}</p>
      <div class="check-grid spaced-grid">
        ${scoreCell("Pass", counts.PASS || 0)}
        ${scoreCell("Fail", counts.FAIL || 0)}
        ${scoreCell("Missing", counts.MISSING || 0)}
        ${scoreCell("N/A", counts.NOT_APPLICABLE || 0)}
      </div>
      ${
        validation.missing_requirements?.length
          ? `<h3 class="subsection-title">Missing requirements</h3>${renderSimpleList(
              unique(validation.missing_requirements),
              "detail-list",
            )}`
          : ""
      }
    </section>`;
}

function renderSourceEndpoints(endpoints) {
  if (!endpoints.length) return "";
  return `
    <section class="drawer-section">
      <h3>Source endpoints</h3>
      <ul class="detail-list">
        ${endpoints
          .map(
            (endpoint) =>
              `<li><span class="record-id">${escapeHtml(endpoint.id)}</span> ${escapeHtml(
                endpoint.method,
              )} <span class="mono">${escapeHtml(endpoint.path)}</span></li>`,
          )
          .join("")}
      </ul>
    </section>`;
}

function openEndpoint(endpointId) {
  const endpoint = state.cache.endpoints?.endpoints.find((item) => item.id === endpointId);
  if (!endpoint) return;
  openDrawer(`
    <header class="drawer-header">
      <p class="eyebrow">${escapeHtml(endpoint.id)} / normalized endpoint</p>
      <h2><span class="method ${slug(endpoint.method)}">${escapeHtml(
        endpoint.method,
      )}</span> ${escapeHtml(endpoint.path)}</h2>
      <div class="drawer-tags">${pill(endpoint.classification.primary)} ${pill(
        endpoint.disposition,
      )} ${pill(endpoint.knowledge_status)}</div>
    </header>
    <section class="drawer-section">
      <h3>Security relevance</h3>
      <div class="score-grid">
        ${scoreCell("Relevance", `${endpoint.security_relevance}/10`)}
        ${scoreCell("Observations", endpoint.observations)}
        ${scoreCell("Parameters", endpoint.parameters.length)}
        ${scoreCell("Path shapes", endpoint.normalization.observed_paths)}
      </div>
    </section>
    <section class="drawer-section">
      <h3>Inferred operation</h3>
      <p>${escapeHtml(endpoint.action.name)} on ${escapeHtml(endpoint.resource.type)}. ${
        endpoint.state_change ? "State-changing behavior is inferred." : "No state change is inferred."
      }</p>
    </section>
    ${drawerListSection("Classification reasons", endpoint.classification.reasons)}
    ${drawerListSection("Relevance reasons", endpoint.relevance_reasons)}
    <section class="drawer-section">
      <h3>Observed coverage</h3>
      <p>Hosts: ${escapeHtml(endpoint.hosts.join(", ") || "None")}</p>
      <p class="spaced-line">Channels: ${escapeHtml(endpoint.channels.join(", ") || "Unknown")}</p>
    </section>
    <section class="drawer-section">
      <h3>Parameters</h3>
      ${
        endpoint.parameters.length
          ? `<ul class="detail-list">${endpoint.parameters
              .map(
                (parameter) =>
                  `<li><span class="record-id">${escapeHtml(parameter.name)}</span> / ${escapeHtml(
                    parameter.location,
                  )} / ${escapeHtml(parameter.semantic_type)}</li>`,
              )
              .join("")}</ul>`
          : "<p>No normalized parameters are recorded.</p>"
      }
    </section>
  `);
}

async function openReport(filename) {
  openDrawer(`<div class="loading-state"><p>Loading report revision...</p></div>`);
  try {
    const data = await api(workspaceApi(`reports/${encodeURIComponent(filename)}`));
    drawerContent.innerHTML = `
      <header class="drawer-header"><p class="eyebrow">Immutable report revision</p><h2>${escapeHtml(
        data.filename,
      )}</h2></header>
      <section class="drawer-section"><div class="markdown-body">${markdownToHtml(
        data.content,
      )}</div></section>`;
  } catch (error) {
    drawerContent.innerHTML = `<div class="error-state"><p>${escapeHtml(error.message)}</p></div>`;
  }
}

async function openDeletionReview(mode) {
  openDrawer(`<div class="loading-state"><p>Validating permanent deletion targets...</p></div>`);
  try {
    const preview = await api(workspaceApi(`deletion-preview?mode=${encodeURIComponent(mode)}`));
    drawerContent.innerHTML = renderDeletionReview(preview);
    updateDeletionSubmit();
  } catch (error) {
    drawerContent.innerHTML = `<div class="error-state"><p>${escapeHtml(error.message)}</p></div>`;
  }
}

function renderDeletionReview(preview) {
  const purge = preview.mode === "purge";
  const credentialStore = preview.targets.credential_store;
  const captures = preview.targets.capture_directory;
  return `
    <header class="drawer-header deletion-header">
      <p class="eyebrow">Danger zone / ${purge ? "complete purge" : "workspace only"}</p>
      <h2>${purge ? "Purge all project data" : "Delete this workspace"}</h2>
      <p>${escapeHtml(preview.workspace.name)} / <span class="record-id">${escapeHtml(
        preview.workspace.slug,
      )}</span></p>
    </header>
    <div class="deletion-mode-picker" role="group" aria-label="Deletion mode">
      <button class="${purge ? "" : "is-active"}" type="button" data-deletion-mode="delete">Workspace only</button>
      <button class="${purge ? "is-active" : ""}" type="button" data-deletion-mode="purge">Complete purge</button>
    </div>
    <section class="drawer-section">
      <h3>Permanent removal preview</h3>
      <div class="deletion-targets">
        ${deletionTargetRow("Workspace", preview.targets.workspace, "Will be removed")}
        ${
          purge
            ? deletionTargetRow(
                "Credential store",
                credentialStore.path,
                credentialStore.present
                  ? `${formatNumber(credentialStore.files)} file(s) will be removed`
                  : "Not present",
              ) +
              deletionTargetRow(
                "Capture directory",
                captures.path,
                captures.present ? "Will be removed" : "Not present",
              )
            : deletionTargetRow(
                "Related local data",
                "Credential store and capture directory",
                "Preserved",
                true,
              )
        }
      </div>
    </section>
    <section class="drawer-section">
      <div class="deletion-warning">
        <strong>No undo is available.</strong>
        <p>${
          purge
            ? "This removes the workspace, observations, models, hypotheses, plans, evidence, reports, actor credentials, and original capture directory."
            : "This removes the workspace, observations, models, hypotheses, plans, evidence, and reports. Credentials and captures remain outside it."
        }</p>
      </div>
      <form id="workspace-delete-form" data-deletion-mode="${escapeAttribute(preview.mode)}">
        <label class="field">
          <span>Type <code>${escapeHtml(preview.expected_confirmation)}</code> to confirm</span>
          <input
            name="confirmation"
            data-expected-confirmation="${escapeAttribute(preview.expected_confirmation)}"
            autocomplete="off"
            spellcheck="false"
            required
          >
        </label>
        <label class="confirm-check deletion-understanding">
          <input name="understood" type="checkbox" required>
          <span>I understand that these validated paths will be permanently removed.</span>
        </label>
        <button class="danger-button danger-submit" type="submit" disabled>
          ${purge ? "Permanently purge project" : "Permanently delete workspace"}
        </button>
        <p class="form-status" id="deletion-status" role="status"></p>
      </form>
    </section>`;
}

function deletionTargetRow(title, path, disposition, preserved = false) {
  return `
    <div class="deletion-target ${preserved ? "is-preserved" : ""}">
      <div><strong>${escapeHtml(title)}</strong><span>${escapeHtml(disposition)}</span></div>
      <code>${escapeHtml(path)}</code>
    </div>`;
}

function handleContentClick(event) {
  const reviewDeletion = event.target.closest("[data-review-deletion]");
  if (reviewDeletion) {
    openDeletionReview(reviewDeletion.dataset.reviewDeletion);
    return;
  }
  const deletionMode = event.target.closest("[data-deletion-mode]");
  if (deletionMode && deletionMode.tagName === "BUTTON") {
    openDeletionReview(deletionMode.dataset.deletionMode);
    return;
  }
  const addAccount = event.target.closest("[data-add-account]");
  if (addAccount) {
    const list = document.querySelector("#setup-account-list");
    list.insertAdjacentHTML("beforeend", setupAccountRow(state.setupAccountIndex));
    state.setupAccountIndex += 1;
    return;
  }
  const removeAccount = event.target.closest("[data-remove-account]");
  if (removeAccount) {
    const rows = document.querySelectorAll("[data-account-row]");
    if (rows.length <= 1) {
      showToast("Setup requires at least one controlled actor label.");
      return;
    }
    removeAccount.closest("[data-account-row]").remove();
    return;
  }
  const initialize = event.target.closest("[data-initialize-capture]");
  if (initialize) {
    initializeCapture();
    return;
  }
  const upload = event.target.closest("[data-upload-hars]");
  if (upload) {
    uploadCaptures();
    return;
  }
  const rerunWorkflow = event.target.closest("[data-rerun-workflow]");
  if (rerunWorkflow) {
    const form = document.querySelector("#ingest-form");
    if (form?.reportValidity()) submitIngest(form, true);
    return;
  }
  const authCheck = event.target.closest("[data-auth-check]");
  if (authCheck) {
    refreshAuthentication(authCheck);
    return;
  }
  const copy = event.target.closest("[data-copy]");
  if (copy) {
    navigator.clipboard
      .writeText(copy.dataset.copy)
      .then(() => showToast("Command copied."))
      .catch(() => showToast("Clipboard access is unavailable."));
    return;
  }
  const viewLink = event.target.closest("[data-view-link]");
  if (viewLink) {
    navigate(viewLink.dataset.viewLink);
    return;
  }
  const documentButton = event.target.closest("[data-document]");
  if (documentButton) {
    loadDocument(documentButton.dataset.document);
    return;
  }
  const reportButton = event.target.closest("[data-report]");
  if (reportButton) {
    openReport(reportButton.dataset.report);
    return;
  }
  const record = event.target.closest("[data-record]");
  if (record?.dataset.record === "hypothesis") openHypothesis(record.dataset.id);
  if (record?.dataset.record === "endpoint") openEndpoint(record.dataset.id);
}

function handleContentInput(event) {
  if (event.target.closest("#workspace-delete-form")) updateDeletionSubmit();
  if (event.target.id === "setup-name") {
    const slugInput = document.querySelector("#setup-slug");
    if (slugInput && slugInput.dataset.edited !== "true") {
      slugInput.value = slugify(event.target.value);
    }
  }
  if (event.target.id === "setup-slug") event.target.dataset.edited = "true";
  if (event.target.id === "har-upload-input") {
    const selection = document.querySelector("#upload-selection");
    const files = [...event.target.files];
    selection.textContent = files.length
      ? `${files.length} file${files.length === 1 ? "" : "s"} / ${formatBytes(
          files.reduce((total, file) => total + file.size, 0),
        )}`
      : "No files selected";
  }
  if (event.target.id === "hypothesis-search") {
    state.hypothesisFilters.query = event.target.value;
    updateHypothesisResults();
  }
  if (event.target.id === "hypothesis-kind") {
    state.hypothesisFilters.kind = event.target.value;
    updateHypothesisResults();
  }
  if (event.target.id === "hypothesis-priority") {
    state.hypothesisFilters.priority = event.target.value;
    updateHypothesisResults();
  }
  if (event.target.id === "endpoint-search") {
    state.endpointFilters.query = event.target.value;
    updateEndpointResults();
  }
  if (event.target.id === "endpoint-classification") {
    state.endpointFilters.classification = event.target.value;
    updateEndpointResults();
  }
  if (event.target.id === "endpoint-disposition") {
    state.endpointFilters.disposition = event.target.value;
    updateEndpointResults();
  }
}

function handleContentSubmit(event) {
  if (event.target.id === "setup-form") {
    event.preventDefault();
    submitSetup(event.target);
  }
  if (event.target.id === "ingest-form") {
    event.preventDefault();
    submitIngest(event.target);
  }
  if (event.target.id === "workspace-delete-form") {
    event.preventDefault();
    submitWorkspaceDeletion(event.target);
  }
}

function updateDeletionSubmit() {
  const form = drawerContent.querySelector("#workspace-delete-form");
  if (!form) return;
  const confirmation = form.elements.confirmation;
  const expected = confirmation.dataset.expectedConfirmation;
  const enabled = confirmation.value === expected && form.elements.understood.checked;
  form.querySelector('button[type="submit"]').disabled = !enabled;
}

async function submitSetup(form) {
  const status = document.querySelector("#setup-status");
  const submit = form.querySelector('button[type="submit"]');
  const accounts = [...form.querySelectorAll("[data-account-row]")].map((row) => ({
    label: row.querySelector('[name="account_label"]').value.trim(),
    role: row.querySelector('[name="account_role"]').value.trim(),
    authenticated: row.querySelector('[name="account_authenticated"]').checked,
    verification_level: "unknown",
    channel: row.querySelector('[name="account_channel"]').value,
  }));
  const hosts = form.elements.hosts.value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
  const payload = {
    project_name: form.elements.project_name.value.trim(),
    slug: form.elements.slug.value.trim(),
    hosts,
    accounts,
    production: form.elements.environment.value === "production",
    base_url: form.elements.base_url.value.trim() || null,
  };
  setButtonBusy(submit, true, "Creating workspace...");
  status.textContent = "Validating scope and creating the local workspace...";
  status.className = "form-status is-working";
  try {
    const result = await writeJson("/api/setup", payload);
    await refreshWorkspaceCatalog(result.workspace.key);
    state.cache = {};
    state.overview = null;
    state.lastIngestResult = null;
    await loadOverview();
    showToast(`Workspace ${result.workspace.name} created.`);
    navigate("ingest");
  } catch (error) {
    status.textContent = error.message;
    status.className = "form-status is-error";
  } finally {
    setButtonBusy(submit, false, "Create workspace");
  }
}

async function refreshWorkspaceCatalog(selectedKey = state.workspaceKey) {
  const payload = await api("/api/workspaces");
  state.workspaces = payload.workspaces.filter((workspace) => workspace.valid);
  const selected = state.workspaces.find((workspace) => workspace.key === selectedKey);
  state.workspaceKey = selected?.key || state.workspaces[0]?.key || null;
  if (state.workspaceKey) window.localStorage.setItem("finsec-workspace", state.workspaceKey);
  else window.localStorage.removeItem("finsec-workspace");
  renderWorkspaceOptions();
}

async function submitWorkspaceDeletion(form) {
  const mode = form.dataset.deletionMode;
  const confirmation = form.elements.confirmation.value;
  const expected = form.elements.confirmation.dataset.expectedConfirmation;
  const status = form.querySelector("#deletion-status");
  const button = form.querySelector('button[type="submit"]');
  if (confirmation !== expected || !form.elements.understood.checked) {
    status.textContent = "The exact confirmation and permanence acknowledgement are required.";
    status.className = "form-status is-error";
    return;
  }
  const endpoint = workspaceApi("delete");
  setButtonBusy(button, true, mode === "purge" ? "Purging permanently..." : "Deleting permanently...");
  status.textContent = "Revalidating every path immediately before permanent removal...";
  status.className = "form-status is-working";
  try {
    const result = await api(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Finsec-UI": "1",
        "X-Finsec-Destructive": "workspace-delete",
      },
      body: JSON.stringify({ mode, confirmation, acknowledged: true }),
    });
    state.cache = {};
    state.overview = null;
    state.lastIngestResult = null;
    closeDrawer();
    await refreshWorkspaceCatalog(null);
    if (state.workspaceKey) {
      await loadOverview();
      await navigate("overview");
    } else {
      await navigate("setup");
    }
    showToast(
      result.mode === "purge"
        ? `Project ${result.slug} permanently purged.`
        : `Workspace ${result.slug} permanently deleted; related data was preserved.`,
    );
  } catch (error) {
    status.textContent = error.message;
    status.className = "form-status is-error";
  } finally {
    setButtonBusy(
      button,
      false,
      mode === "purge" ? "Permanently purge project" : "Permanently delete workspace",
    );
    updateDeletionSubmit();
  }
}

async function initializeCapture() {
  setLoading("Initializing the external capture directory...");
  try {
    state.cache.ingest = await api(workspaceApi("ingest/initialize"), {
      method: "POST",
      headers: { "X-Finsec-UI": "1" },
    });
    renderIngest(state.cache.ingest);
    showToast("Capture directory initialized.");
  } catch (error) {
    renderError(error);
  }
}

async function refreshAuthentication(button) {
  const actorId = button.dataset.authCheck;
  setButtonBusy(button, true, "Checking locally...");
  try {
    state.cache.authentication = await api(workspaceApi("authentication"));
    renderAuthentication(state.cache.authentication);
    showToast(`Local authentication preflight refreshed for ${actorId}. Zero requests sent.`);
  } catch (error) {
    renderError(error);
  } finally {
    setButtonBusy(button, false, "Check locally again");
  }
}

async function uploadCaptures() {
  const input = document.querySelector("#har-upload-input");
  const reviewed = document.querySelector("#upload-reviewed");
  const status = document.querySelector("#upload-status");
  const button = document.querySelector("[data-upload-hars]");
  const files = [...input.files];
  if (!files.length) {
    status.textContent = "Choose at least one HAR file.";
    status.className = "form-status is-error";
    return;
  }
  if (!reviewed.checked) {
    status.textContent = "Confirm the authorization and sanitization review first.";
    status.className = "form-status is-error";
    return;
  }
  setButtonBusy(button, true, "Uploading...");
  status.className = "form-status is-working";
  try {
    for (let index = 0; index < files.length; index += 1) {
      const file = files[index];
      status.textContent = `Storing ${index + 1}/${files.length}: ${file.name}`;
      await api(`${workspaceApi("ingest/upload")}?filename=${encodeURIComponent(file.name)}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          "X-Finsec-UI": "1",
          "X-Finsec-Reviewed": "true",
        },
        body: file,
      });
    }
    state.cache.ingest = await api(workspaceApi("ingest"));
    renderIngest(state.cache.ingest);
    showToast(`${files.length} reviewed HAR file${files.length === 1 ? "" : "s"} stored.`);
  } catch (error) {
    status.textContent = error.message;
    status.className = "form-status is-error";
  } finally {
    setButtonBusy(button, false, "Upload selected HARs");
  }
}

async function submitIngest(form, forceWorkflow = false) {
  const status = document.querySelector("#ingest-status");
  const button = forceWorkflow
    ? form.querySelector("[data-rerun-workflow]")
    : form.querySelector('button[type="submit"]');
  const assignments = [...form.querySelectorAll("[data-capture-file]")].map((row) => ({
    file: row.dataset.captureFile,
    actor: row.querySelector('[name="capture_actor"]').value || null,
    channel: row.querySelector('[name="capture_channel"]').value || null,
    enabled: row.querySelector('[name="capture_enabled"]').checked,
  }));
  const incomplete = assignments.find(
    (item) => item.enabled && (!item.actor || !item.channel),
  );
  if (incomplete) {
    status.textContent = `Choose an actor and channel for ${incomplete.file}.`;
    status.className = "form-status is-error";
    return;
  }
  const payload = {
    assignments,
    reviewed: form.elements.reviewed.checked,
    run_analysis: forceWorkflow || form.elements.run_analysis.checked,
  };
  const idleLabel = forceWorkflow ? "Run passive workflow again" : "Ingest selected captures";
  setButtonBusy(
    button,
    true,
    payload.run_analysis ? "Running passive workflow..." : "Ingesting...",
  );
  status.textContent = forceWorkflow
    ? "Rerunning ingestion and rebuilding the complete passive research pipeline from the reviewed manifest..."
    : payload.run_analysis
      ? "Importing reviewed captures and rebuilding deterministic research artifacts..."
      : "Importing reviewed captures without downstream regeneration...";
  status.className = "form-status is-working";
  try {
    const result = await writeJson(workspaceApi("ingest/run"), payload);
    state.lastIngestResult = result;
    state.cache = {};
    state.overview = null;
    await loadOverview();
    state.cache.ingest = await api(workspaceApi("ingest"));
    renderIngest(state.cache.ingest, result);
    showToast(
      forceWorkflow
        ? "Passive workflow rerun completed. No target request was sent."
        : "Passive ingestion completed. No target request was sent.",
    );
  } catch (error) {
    status.textContent = error.message;
    status.className = "form-status is-error";
  } finally {
    setButtonBusy(button, false, idleLabel);
  }
}

function setButtonBusy(button, busy, labelText) {
  if (!button) return;
  button.disabled = busy;
  button.textContent = labelText;
}

function openDrawer(html) {
  drawerContent.innerHTML = html;
  drawerBackdrop.hidden = false;
  drawer.setAttribute("aria-hidden", "false");
  window.requestAnimationFrame(() => drawer.classList.add("is-open"));
  document.body.style.overflow = "hidden";
}

function closeDrawer() {
  drawer.classList.remove("is-open");
  drawer.setAttribute("aria-hidden", "true");
  drawerBackdrop.hidden = true;
  document.body.style.overflow = "";
}

function renderCoverage(items) {
  if (!items.length) return renderInlineEmpty("No passive observation coverage exists yet.");
  const maximum = Math.max(...items.map((item) => item.count), 1);
  return `<div class="mini-list">${items
    .map(
      (item) => `
        <div class="coverage-row">
          <span class="record-id">${escapeHtml(label(item.label))}</span>
          <span class="coverage-track"><i class="coverage-${coverageStep(
            item.count,
            maximum,
          )}"></i></span>
          <span class="coverage-value mono">${formatNumber(item.count)}</span>
        </div>`,
    )
    .join("")}</div>`;
}

function pageHeading(eyebrow, title, description) {
  return `
    <header class="page-heading">
      <div class="heading-copy"><p class="eyebrow">${escapeHtml(eyebrow)}</p><h1>${escapeHtml(
        title,
      )}</h1><p>${escapeHtml(description)}</p></div>
    </header>`;
}

function statCard(index, value, title, accent = false) {
  return `<article class="stat-card ${accent ? "accent" : ""}"><span class="stat-index">${escapeHtml(
    index,
  )}</span><strong>${formatNumber(value)}</strong><span>${escapeHtml(title)}</span></article>`;
}

function summaryCard(title, value) {
  return `<article class="summary-card"><span>${escapeHtml(title)}</span><strong>${formatNumber(
    value,
  )}</strong></article>`;
}

function scoreCell(title, value) {
  return `<div class="score-cell"><strong>${escapeHtml(value)}</strong><span>${escapeHtml(
    title,
  )}</span></div>`;
}

function searchField(id, placeholder, value) {
  return `<label class="search-field"><span class="sr-only">${escapeHtml(
    placeholder,
  )}</span><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6.5"></circle><path d="m16 16 4 4"></path></svg><input id="${escapeAttribute(
    id,
  )}" type="search" value="${escapeAttribute(value)}" placeholder="${escapeAttribute(
    placeholder,
  )}" autocomplete="off"></label>`;
}

function filterSelect(id, options, selected) {
  return `<select class="filter-select" id="${escapeAttribute(id)}">${options
    .map(
      ([value, text]) =>
        `<option value="${escapeAttribute(value)}" ${value === selected ? "selected" : ""}>${escapeHtml(
          text,
        )}</option>`,
    )
    .join("")}</select>`;
}

function pill(value, overrideClass = null) {
  const text = value || "Unknown";
  let className = overrideClass || slug(text);
  if (text.startsWith("SUPPRESSED")) className = "suppressed";
  return `<span class="pill ${escapeAttribute(className)}">${escapeHtml(label(text))}</span>`;
}

function drawerTextSection(title, text) {
  if (!text) return "";
  return `<section class="drawer-section"><h3>${escapeHtml(title)}</h3><p>${escapeHtml(
    text,
  )}</p></section>`;
}

function drawerListSection(title, items, safety = false) {
  if (!items?.length) return "";
  if (safety) {
    return `<section class="drawer-section"><h3>${escapeHtml(
      title,
    )}</h3><div class="safety-note">${items.map(escapeHtml).join("<br>")}</div></section>`;
  }
  return `<section class="drawer-section"><h3>${escapeHtml(title)}</h3>${renderSimpleList(
    items,
    "detail-list",
  )}</section>`;
}

function renderSimpleList(items, className, code = false) {
  if (!items?.length) return `<p class="empty-inline">None recorded.</p>`;
  return `<ul class="${escapeAttribute(className)}">${items
    .map((item) => `<li>${code ? `<code>${escapeHtml(item)}</code>` : escapeHtml(item)}</li>`)
    .join("")}</ul>`;
}

function renderInlineEmpty(message) {
  return `<div class="empty-large">${escapeHtml(
    message,
  )}</div>`;
}

function renderNoWorkspaces(workspaces) {
  const invalid = workspaces.filter((workspace) => !workspace.valid);
  workspaceSelect.innerHTML = `<option>No workspaces found</option>`;
  content.innerHTML = `
    <div class="empty-state">
      <div>
        <p class="eyebrow">No local target selected</p>
        <h1 class="empty-heading">Create a workspace first.</h1>
        <p>Run <code>hunt setup</code>, then refresh this page.</p>
        ${invalid.length ? `<p>${formatNumber(invalid.length)} invalid workspace entries were skipped.</p>` : ""}
      </div>
    </div>`;
}

function renderError(error) {
  content.innerHTML = `
    <div class="error-state">
      <div><p class="eyebrow">Local data error</p><h1 class="error-heading">The workspace could not be rendered.</h1><p>${escapeHtml(
        error.message || String(error),
      )}</p></div>
    </div>`;
}

function setLoading(message) {
  content.innerHTML = `<div class="loading-state"><div class="loader-mark"><span></span><span></span><span></span></div><p>${escapeHtml(
    message,
  )}</p></div>`;
}

let toastTimer;
function showToast(message) {
  window.clearTimeout(toastTimer);
  toast.textContent = message;
  toast.classList.add("is-visible");
  toastTimer = window.setTimeout(() => toast.classList.remove("is-visible"), 2200);
}

function markdownToHtml(markdown) {
  const lines = String(markdown || "").replaceAll("\r\n", "\n").split("\n");
  const output = [];
  let inCode = false;
  let listType = null;
  const closeList = () => {
    if (listType) output.push(`</${listType}>`);
    listType = null;
  };
  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (line.startsWith("```")) {
      closeList();
      if (inCode) output.push("</code></pre>");
      else output.push("<pre><code>");
      inCode = !inCode;
      continue;
    }
    if (inCode) {
      output.push(`${escapeHtml(rawLine)}\n`);
      continue;
    }
    if (!line.trim()) {
      closeList();
      continue;
    }
    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      closeList();
      const level = heading[1].length;
      output.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
      continue;
    }
    const unordered = line.match(/^\s*[-*]\s+(.+)$/);
    if (unordered) {
      if (listType !== "ul") {
        closeList();
        output.push("<ul>");
        listType = "ul";
      }
      output.push(`<li>${inlineMarkdown(unordered[1])}</li>`);
      continue;
    }
    const ordered = line.match(/^\s*\d+\.\s+(.+)$/);
    if (ordered) {
      if (listType !== "ol") {
        closeList();
        output.push("<ol>");
        listType = "ol";
      }
      output.push(`<li>${inlineMarkdown(ordered[1])}</li>`);
      continue;
    }
    closeList();
    output.push(`<p>${inlineMarkdown(line)}</p>`);
  }
  closeList();
  if (inCode) output.push("</code></pre>");
  return output.join("");
}

function inlineMarkdown(text) {
  return escapeHtml(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
}

function unique(items) {
  return [...new Set(items)];
}

function coverageStep(value, maximum) {
  const percentage = Math.max(5, Math.round((value / maximum) * 20) * 5);
  return Math.min(100, percentage);
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value) || 0);
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function formatRemaining(value) {
  if (value === null || value === undefined) return "Unknown";
  const seconds = Number(value);
  if (seconds <= 0) return "Expired";
  if (seconds < 60) return `${Math.floor(seconds)} seconds`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours`;
  return `${Math.floor(seconds / 86400)} days`;
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "recently";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function label(value) {
  return String(value || "Unknown")
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function slug(value) {
  return String(value || "unknown")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

function slugify(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 64)
    .replace(/-$/, "");
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll("`", "&#096;");
}

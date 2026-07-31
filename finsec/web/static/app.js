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

const state = {
  workspaces: [],
  workspaceKey: null,
  overview: null,
  cache: {},
  view: "overview",
  hypothesisFilters: { kind: "ALL", priority: "ALL", query: "" },
  endpointFilters: { classification: "ALL", disposition: "ALL", query: "" },
};

const VIEW_LABELS = {
  overview: "OVERVIEW",
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
      renderNoWorkspaces(payload.workspaces);
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
    await loadOverview();
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
    if (!state.overview) await loadOverview();
    if (view === "overview") renderOverview(state.overview);
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
  return `/api/workspaces/${encodeURIComponent(state.workspaceKey)}/${path}`;
}

async function api(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `Request failed with ${response.status}`);
  return payload;
}

function renderWorkspaceOptions() {
  workspaceSelect.innerHTML = state.workspaces
    .map(
      (workspace) =>
        `<option value="${escapeHtml(workspace.key)}" ${
          workspace.key === state.workspaceKey ? "selected" : ""
        }>${escapeHtml(workspace.name)}</option>`,
    )
    .join("");
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
        <div class="command-row">
          <code>${escapeHtml(data.next_action.command)}</code>
          <button class="copy-button" type="button" data-copy="${escapeAttribute(
            data.next_action.command,
          )}">COPY</button>
        </div>
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

function handleContentClick(event) {
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

function pill(value) {
  const text = value || "Unknown";
  let className = slug(text);
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

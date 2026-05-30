const reportText = document.querySelector("#reportText");
const sourceName = document.querySelector("#sourceName");
const statusBox = document.querySelector("#statusBox");
const exportBox = document.querySelector("#exportBox");
const indicatorRows = document.querySelector("#indicatorRows");
const clusterGrid = document.querySelector("#clusterGrid");
const summaryCards = document.querySelector("#summaryCards");
const apiDocsLink = document.querySelector("#apiDocsLink");

const demoReport = `Public report excerpt:
Observed infrastructure:
- hxxp://secure-login-update.example-attacker.net/session
- c2.panel.example-attacker.net
- 185.199.108.153
- operator@example-attacker.net

File indicators:
- e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- 44d88612fea8a8f36de82e1278abb02f

Analyst note: login-themed URL was associated with credential harvesting attempts.`;

function tagList(tags) {
  if (!tags || tags.length === 0) {
    return "<span class=\"pill\">none</span>";
  }
  return tags.map((tag) => `<span class="pill">${escapeHtml(tag)}</span>`).join("");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#039;");
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${text}`);
  }
  return response.json();
}

function renderIndicators(indicators) {
  indicatorRows.innerHTML = "";
  if (indicators.length === 0) {
    indicatorRows.innerHTML = "<tr><td colspan=\"6\">No indicators ingested yet.</td></tr>";
    return;
  }
  for (const indicator of indicators) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${escapeHtml(indicator.type)}</td>
      <td><code>${escapeHtml(indicator.value)}</code></td>
      <td class="severity-${escapeHtml(indicator.severity)}">${escapeHtml(indicator.severity)}</td>
      <td>${escapeHtml(indicator.score)}</td>
      <td>${tagList(indicator.tags)}</td>
      <td>${escapeHtml((indicator.explanation || []).join("; "))}</td>
    `;
    indicatorRows.appendChild(row);
  }
}

function renderSummary(indicators) {
  const counts = indicators.reduce(
    (accumulator, indicator) => {
      accumulator.total += 1;
      accumulator[indicator.severity] = (accumulator[indicator.severity] || 0) + 1;
      return accumulator;
    },
    { total: 0 },
  );
  summaryCards.innerHTML = ["total", "critical", "high", "medium", "low", "informational"]
    .map(
      (key) => `
        <div class="summary-card">
          <strong>${counts[key] || 0}</strong>
          <span>${key}</span>
        </div>
      `,
    )
    .join("");
}

function renderClusters(clusters) {
  clusterGrid.innerHTML = "";
  if (clusters.length === 0) {
    clusterGrid.innerHTML = "<p>No clusters yet.</p>";
    return;
  }
  for (const cluster of clusters) {
    const card = document.createElement("article");
    card.className = "cluster-card";
    const members = cluster.indicators
      .map((indicator) => `<li>${escapeHtml(indicator.type)}: ${escapeHtml(indicator.value)}</li>`)
      .join("");
    card.innerHTML = `
      <h3>${escapeHtml(cluster.title)}</h3>
      <p>Score: <strong>${escapeHtml(cluster.score)}</strong></p>
      <p>${tagList(cluster.shared_tags)}</p>
      <ul>${members}</ul>
    `;
    clusterGrid.appendChild(card);
  }
}

async function refresh() {
  const [indicators, clusterResponse] = await Promise.all([
    requestJson("/api/indicators"),
    requestJson("/api/clusters"),
  ]);
  renderIndicators(indicators);
  renderSummary(indicators);
  renderClusters(clusterResponse.clusters);
}

async function configureApiDocsLink() {
  try {
    const config = await requestJson("/api/config");
    if (config.docs_enabled && config.docs_url) {
      apiDocsLink.href = config.docs_url;
      apiDocsLink.hidden = false;
      return;
    }
  } catch (error) {
    console.warn("Unable to load API docs config", error);
  }
  apiDocsLink.hidden = true;
}

document.querySelector("#demoButton").addEventListener("click", () => {
  reportText.value = demoReport;
});

document.querySelector("#analyzeButton").addEventListener("click", async () => {
  statusBox.textContent = "Analyzing report...";
  try {
    const result = await requestJson("/api/intake", {
      method: "POST",
      body: JSON.stringify({
        source_name: sourceName.value || "manual-report",
        text: reportText.value,
      }),
    });
    statusBox.textContent = `Extracted ${result.extracted_count} IOC(s), saved ${result.new_or_updated_count}.`;
    await refresh();
  } catch (error) {
    statusBox.textContent = `Error: ${error.message}`;
  }
});

document.querySelector("#exportButton").addEventListener("click", async () => {
  exportBox.textContent = "Generating export...";
  try {
    const result = await requestJson("/api/export", {
      method: "POST",
      body: JSON.stringify({ format: document.querySelector("#exportFormat").value }),
    });
    exportBox.textContent = result.content;
  } catch (error) {
    exportBox.textContent = `Error: ${error.message}`;
  }
});

document.querySelector("#refreshButton").addEventListener("click", refresh);

document.querySelector("#clearButton").addEventListener("click", async () => {
  await requestJson("/api/indicators", { method: "DELETE" });
  exportBox.textContent = "No export generated yet.";
  statusBox.textContent = "Cleared local indicator database.";
  await refresh();
});

configureApiDocsLink();

refresh().catch((error) => {
  statusBox.textContent = `Error loading dashboard: ${error.message}`;
});

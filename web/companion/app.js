/* ProofMesh Companion — client-side evidence browser (no remote execution). */
(function () {
  "use strict";

  let evidence = null;

  const $ = (id) => document.getElementById(id);
  const emptyEl = $("empty");
  const dashEl = $("dashboard");
  const fileInput = $("fileInput");
  const clearBtn = $("clearBtn");

  function badge(status) {
    const s = String(status || "unknown").toLowerCase();
    return `<span class="badge ${s}">${s}</span>`;
  }

  function showDashboard(ev) {
    evidence = ev;
    emptyEl.classList.add("hidden");
    dashEl.classList.remove("hidden");
    clearBtn.disabled = false;

    const summary = ev.summary || {};
    const repo = ev.repository || {};
    const integrity = ev.integrity || {};
    const overall = summary.overall_status || "unknown";
    $("overallStatus").textContent = overall;
    $("overallStatus").className = "big " + overall;
    $("runMeta").textContent = `Run ${ev.run_id || "—"} · ${ev.created_at || ""}`;

    $("repoMeta").innerHTML = [
      ["Root", repo.root || "—"],
      ["Commit", repo.head_commit_short || repo.head_commit || "—"],
      ["Branch", repo.branch || (repo.is_detached ? "(detached)" : "—")],
      ["Dirty", repo.is_dirty ? "yes" : "no"],
      ["Git", repo.is_git ? "yes" : "no"],
    ]
      .map(([k, v]) => `<dt>${k}</dt><dd>${escapeHtml(String(v))}</dd>`)
      .join("");

    $("integrityMeta").innerHTML = [
      ["Algorithm", integrity.algorithm || "—"],
      ["Content hash", integrity.content_hash || "—"],
      ["Signed", integrity.signed ? "yes" : "no"],
      ["Note", integrity.note || "Hash alone is not a digital signature."],
    ]
      .map(([k, v]) => `<dt>${k}</dt><dd>${escapeHtml(String(v))}</dd>`)
      .join("");

    const counts = summary.check_counts || {};
    $("checkCounts").textContent =
      `passed=${counts.passed || 0} failed=${counts.failed || 0} ` +
      `skipped=${counts.skipped || 0} errored=${counts.errored || 0}`;

    const tbody = $("checksTable").querySelector("tbody");
    tbody.innerHTML = "";
    (ev.checks || []).forEach((c) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(c.check_id || "")}</td>
        <td>${badge(c.status)}</td>
        <td>${(c.findings || []).length}</td>
        <td>${Math.round(c.duration_ms || 0)} ms</td>
        <td>${escapeHtml((c.message || "").slice(0, 120))}</td>`;
      tbody.appendChild(tr);
    });

    renderFindings();
    renderSuppressed();
    const lim = $("limitationsList");
    lim.innerHTML = "";
    (ev.limitations || []).forEach((x) => {
      const li = document.createElement("li");
      li.textContent = x;
      lim.appendChild(li);
    });
  }

  function allFindings() {
    const out = [];
    (evidence.checks || []).forEach((c) => {
      (c.findings || []).forEach((f) => out.push(f));
    });
    return out;
  }

  function renderFindings() {
    const sev = $("sevFilter").value;
    const ruleQ = ($("ruleFilter").value || "").toLowerCase();
    const tbody = $("findingsTable").querySelector("tbody");
    tbody.innerHTML = "";
    let n = 0;
    allFindings().forEach((f) => {
      const s = (f.severity || "").toLowerCase();
      if (sev !== "all" && s !== sev) return;
      if (ruleQ && !(f.rule_id || "").toLowerCase().includes(ruleQ)) return;
      n += 1;
      const loc = f.path + (f.line ? ":" + f.line : "");
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${badge(f.severity || "medium")}</td>
        <td><code>${escapeHtml(f.rule_id || "")}</code></td>
        <td>${escapeHtml(loc)}</td>
        <td>${escapeHtml(f.message || "")}</td>`;
      tbody.appendChild(tr);
    });
    $("findingsEmpty").textContent = n ? "" : "No findings match the current filters.";
  }

  function renderSuppressed() {
    const rows = evidence.suppressed_findings || [];
    const card = $("suppressedCard");
    if (!rows.length) {
      card.classList.add("hidden");
      return;
    }
    card.classList.remove("hidden");
    const tbody = $("suppressedTable").querySelector("tbody");
    tbody.innerHTML = "";
    rows.forEach((r) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${escapeHtml(r.rule_id || "")}</code></td>
        <td>${escapeHtml(r.path || "")}</td>
        <td>${escapeHtml(r.justification || "")}</td>
        <td>${escapeHtml(r.created_by || "")}</td>`;
      tbody.appendChild(tr);
    });
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function clearAll() {
    evidence = null;
    dashEl.classList.add("hidden");
    emptyEl.classList.remove("hidden");
    clearBtn.disabled = true;
    fileInput.value = "";
  }

  fileInput.addEventListener("change", async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    try {
      const text = await file.text();
      const data = JSON.parse(text);
      if (!data || typeof data !== "object" || !data.run_id) {
        alert("This file does not look like a ProofMesh evidence bundle.");
        return;
      }
      showDashboard(data);
    } catch (err) {
      alert("Failed to parse JSON: " + err.message);
    }
  });

  clearBtn.addEventListener("click", clearAll);
  $("sevFilter").addEventListener("change", () => evidence && renderFindings());
  $("ruleFilter").addEventListener("input", () => evidence && renderFindings());
})();

/*
 * NetScope — Web MVP browser app (no framework, no build step).
 * Contract: docs/02 §F, docs/03, docs/04, docs/10-UI-DESIGN-PROPOSAL.md.
 * Pure logic lives in netscope-core.js.
 */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var Core = window.NetScopeCore;
  var View = window.NetScopeView;

  // Frozen: Quick Check default is 12 (AGENTS.md, ADR-003). Do not change here.
  var SAMPLE_COUNT = 12;

  var ENDPOINTS = {
    cloudflare_trace: { name: "Cloudflare trace", url: "https://www.cloudflare.com/cdn-cgi/trace" },
    google_fonts: { name: "Google Fonts API", url: "https://fonts.googleapis.com/css2?family=Roboto" }
  };

  // Web MVP profiles. DNS/TCP/TLS/regional/native require backend or Android.
  var PROFILES = {
    quick_check: { name: "Quick Check", samples: SAMPLE_COUNT, intervalMs: 350, timeoutMs: 5000 },
    latency_monitor: { name: "Latency Monitor", samples: 20, intervalMs: 1000, timeoutMs: 5000 },
    http_diagnostics: { name: "HTTP Diagnostics", samples: SAMPLE_COUNT, intervalMs: 350, timeoutMs: 5000 }
  };

  var running = false;
  var controller = null;
  var chart = null;
  var events = [];
  var session = null;
  var sessionStartedAt = 0;

  function ProbeError(kind, httpStatus) {
    this.kind = kind;
    this.httpStatus = typeof httpStatus === "number" ? httpStatus : null;
  }
  ProbeError.prototype = Object.create(Error.prototype);

  function clampInt(value, min, max, fallback) {
    var n = parseInt(value, 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(Math.max(n, min), max);
  }

  function readConfig() {
    return {
      samples: clampInt($("sampleCountInput").value, 1, 200, SAMPLE_COUNT),
      timeoutMs: clampInt($("timeoutInput").value, 200, 30000, 5000),
      intervalMs: clampInt($("intervalInput").value, 0, 10000, 350),
      profile: $("profile").value,
      targetId: $("target").value
    };
  }

  function applyProfileDefaults() {
    var p = PROFILES[$("profile").value];
    if (!p) return;
    $("sampleCountInput").value = p.samples;
    $("timeoutInput").value = p.timeoutMs;
    $("intervalInput").value = p.intervalMs;
  }

  function initChart() {
    if (!window.Chart) {
      $("chartEmpty").textContent = "Chart library unavailable (CDN). Connect to the internet and reload.";
      return;
    }
    chart = new Chart($("latencyChart"), {
      type: "line",
      data: {
        labels: [],
        datasets: [{
          label: "HTTP response time",
          data: [],
          borderColor: "#50e3ef",
          backgroundColor: "rgba(80,227,239,.12)",
          fill: false,
          tension: 0, // straight segments between measured points; no implied smoothing
          pointRadius: 4,
          pointBackgroundColor: "#50e3ef",
          borderWidth: 2,
          spanGaps: false
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        plugins: { legend: { display: false }, tooltip: { callbacks: { label: function (c) { return c.parsed.y + " ms"; } } } },
        scales: {
          x: { grid: { color: "rgba(135,148,170,.08)" }, ticks: { color: "#71819b", font: { size: 10 } } },
          y: { beginAtZero: true, grid: { color: "rgba(135,148,170,.10)" }, ticks: { color: "#71819b", font: { size: 10 }, callback: function (v) { return v + " ms"; } } }
        }
      }
    });
  }

  function setStatus(text) { $("statusText").textContent = text; }

  function setProgress(done, total) {
    var pct = View.progressPercent(done, total);
    $("progressBar").style.width = pct + "%";
    $("progressTrack").setAttribute("aria-valuenow", String(pct));
    $("progressTrack").setAttribute("aria-valuetext", View.progressText(done, total));
    $("sampleCount").textContent = View.progressText(done, total);
  }

  function renderMetrics() {
    var stats = Core.computeStats(events);
    var cfgSamples = session ? session.config.sample_count : readConfig().samples;

    $("avgLatency").textContent = View.formatMetric(stats.avg);
    $("minLatency").textContent = View.formatMetric(stats.min);
    $("maxLatency").textContent = View.formatMetric(stats.max);
    $("jitter").textContent = View.formatMetric(stats.jitter);

    var medianCard = $("medianLatency").closest(".metric");
    var p95Card = $("p95Latency").closest(".metric");
    if (stats.percentileEligible) {
      $("medianLatency").textContent = View.formatMetric(stats.median);
      $("p95Latency").textContent = View.formatMetric(stats.p95);
      medianCard.classList.remove("gated"); p95Card.classList.remove("gated");
    } else {
      $("medianLatency").textContent = View.DASH;
      $("p95Latency").textContent = View.DASH;
      medianCard.classList.add("gated"); p95Card.classList.add("gated");
    }
    $("medianNote").textContent = View.percentileNote(stats);
    $("p95Note").textContent = View.percentileNote(stats);

    $("failureRate").textContent = View.formatRatePercent(stats.failureRate);
    $("failureNote").textContent = View.rateText(stats.failed, stats.attempted);

    $("success").textContent = stats.attempted ? stats.successful : View.DASH;
    $("success").nextElementSibling.textContent = "/ " + View.successDenominator(stats, cfgSamples);
    $("successNote").textContent = View.successText(stats.successful, stats.attempted);

    updateResultTag(stats);
    var summary = View.summarizeFailures(events);
    updateNotice(summary);
    renderStatusStrip(stats);
    renderHypothesis(summary);
  }

  function updateResultTag(stats) {
    var tag = $("resultTag");
    var r = View.resultTag(stats, session ? session.stop_reason : null, running);
    tag.textContent = r.text;
    tag.setAttribute("data-state", r.state);
  }

  function updateNotice(summary) {
    var notice = $("notice");
    var text = $("noticeText");
    var message = View.noticeText(summary);
    if (message) {
      text.textContent = message;
      notice.setAttribute("role", "status");
      notice.hidden = false;
    } else {
      notice.hidden = true;
    }
  }

  // Status strip (docs/10 §4/§5): one chip per registered target, state + source.
  // Only the active target can carry events; others stay idle. Never a single
  // green/red verdict — the chip state is derived from this session's outcomes.
  function targetState(targetId, stats) {
    if (!session || session.target_id !== targetId) return "idle";
    if (running) return "running";
    if (stats.attempted === 0) return "idle";
    if (stats.failed === 0) return "success";
    if (stats.successful === 0) return "fail";
    return "ambiguous";
  }

  function renderStatusStrip(stats) {
    var mount = $("statusStrip");
    if (!mount) return;
    mount.innerHTML = Object.keys(ENDPOINTS).map(function (id) {
      var ep = ENDPOINTS[id];
      var state = targetState(id, stats);
      var glyph = { idle: "\u25cb", running: "\u25cf", success: "\u25cf", fail: "\u2715", ambiguous: "\u25c7" }[state];
      var word = { idle: "idle", running: "running", success: "last run ok", fail: "last run failed", ambiguous: "ambiguous" }[state];
      return '<li class="chip" data-state="' + state + '">' +
        '<span class="chip-glyph" aria-hidden="true">' + glyph + "</span>" +
        '<span class="chip-name">' + escapeHtml(ep.name) + "</span>" +
        '<span class="chip-state">' + word + "</span>" +
        '<span class="source-badge">browser</span></li>';
    }).join("");
  }

  // Hypothesis panel: only when ambiguous (pre-response) failures exist.
  function renderHypothesis(summary) {
    var panel = $("hypothesis");
    if (!panel) return;
    var text = View.hypothesisText(summary);
    if (text) {
      $("hypothesisText").textContent = text;
      panel.hidden = false;
    } else {
      panel.hidden = true;
    }
  }

  function updateChart() {
    if (!chart) return;
    chart.data.labels = events.map(function (e) { return "#" + e.sequence; });
    chart.data.datasets[0].data = events.map(function (e) { return Number.isFinite(e.duration_ms) ? e.duration_ms : null; });
    chart.update();
    $("chartEmpty").style.display = events.length ? "none" : "grid";
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (char) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char];
    });
  }

  function relativeTime(iso) {
    return View.relativeText(iso, sessionStartedAt);
  }

  function renderEvents() {
    var body = $("eventBody");
    var rows = View.filterEvents(events, $("filterMethod").value, $("filterSource").value);

    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="9" class="empty-row">' + (events.length ? "No events match the current filters." : "No events yet.") + "</td></tr>";
    } else {
      body.innerHTML = rows.map(function (e) {
        var utc = e.timestamp_utc ? e.timestamp_utc.slice(11, 19) : View.DASH;
        var rel = relativeTime(e.timestamp_utc);
        var ov = View.outcomeView(e.outcome);
        return "<tr>" +
          '<td class="num">' + e.sequence + "</td>" +
          "<td>" + utc + (rel ? ' <span class="rel-time">' + rel + "</span>" : "") + "</td>" +
          "<td>" + escapeHtml(e.source) + "</td>" +
          "<td>" + escapeHtml(e.method) + "</td>" +
          '<td><span class="badge-outcome" data-outcome="' + escapeHtml(e.outcome) + '">' +
          '<span class="glyph" aria-hidden="true">' + ov.glyph + "</span>" + escapeHtml(e.outcome) + "</span></td>" +
          "<td>" + escapeHtml(e.error_kind == null ? View.DASH : e.error_kind) + "</td>" +
          '<td class="num">' + (e.http_status == null ? View.DASH : e.http_status) + "</td>" +
          '<td class="num">' + (e.duration_ms == null ? View.DASH : e.duration_ms + " ms") + "</td>" +
          '<td class="num">' + (e.timeout_ms == null ? View.DASH : e.timeout_ms + " ms") + "</td>" +
          "</tr>";
      }).join("");
    }

    var count = $("evidenceCount");
    if (count) {
      var failed = events.filter(function (e) { return e.outcome !== "success"; }).length;
      count.textContent = events.length
        ? events.length + " event" + (events.length === 1 ? "" : "s") + " · " + failed + " not successful"
        : "No events yet";
    }
  }

  function setExportEnabled(enabled) {
    $("exportJson").disabled = !enabled;
    $("exportCsv").disabled = !enabled;
  }

  function updateSessionDetails() {
    $("detailProfile").textContent = session ? session.profile_name : "Not tested";
    $("detailEndpoint").textContent = session ? session.target_name : "Not tested";
    $("stopReason").textContent = session ? session.stop_reason : "\u2014";
  }

  async function probe(url, signal) {
    var started = performance.now();
    var separator = url.indexOf("?") === -1 ? "?" : "&";
    var target = url + separator + "_netscope=" + Date.now() + "-" + Math.random().toString(16).slice(2);
    var response;
    try {
      response = await fetch(target, { method: "GET", mode: "cors", cache: "no-store", signal: signal });
    } catch (err) {
      // Opaque: cause not determinable from the browser (D-2=A).
      throw new ProbeError("network_error");
    }
    if (!response.ok) throw new ProbeError("http_error", response.status);
    return { durationMs: Math.round(performance.now() - started), httpStatus: response.status };
  }

  var sleep = function (ms) { return new Promise(function (resolve) { setTimeout(resolve, ms); }); };

  async function runTest() {
    if (running) return;
    var cfg = readConfig();
    var profile = PROFILES[cfg.profile];
    var target = ENDPOINTS[cfg.targetId];
    if (!profile || !target) return;

    running = true;
    events = [];
    sessionStartedAt = Date.now();
    controller = new AbortController();
    session = {
      id: Core.makeId("session"),
      profile: cfg.profile,
      profile_name: profile.name,
      target_id: cfg.targetId,
      target_name: target.name,
      stop_reason: "completed",
      config: { sample_count: cfg.samples, timeout_ms: cfg.timeoutMs, interval_ms: cfg.intervalMs }
    };

    $("runBtn").disabled = true;
    $("stopBtn").disabled = false;
    $("profile").disabled = true;
    $("target").disabled = true;
    $("sampleCountInput").disabled = true;
    $("timeoutInput").disabled = true;
    $("intervalInput").disabled = true;
    $("lastRun").textContent = new Date().toLocaleString();

    $("progressText").textContent = "Testing\u2026";
    setProgress(0, cfg.samples);
    setStatus("Test running");
    updateSessionDetails();
    renderMetrics();
    updateChart();
    renderEvents();
    setExportEnabled(false);

    for (var i = 0; i < cfg.samples && running; i++) {
      $("progressText").textContent = "Sending sample " + (i + 1) + "\u2026";
      var sampleController = new AbortController();
      var abortParent = function () { sampleController.abort(); };
      controller.signal.addEventListener("abort", abortParent, { once: true });
      var timer = null;
      var timedOut = false;
      var kind = "network_error";
      var httpStatus = null;
      var durationMs = null;

      try {
        var timeoutPromise = new Promise(function (_, reject) {
          timer = setTimeout(function () { timedOut = true; sampleController.abort(); reject(new ProbeError("timeout")); }, cfg.timeoutMs);
        });
        var result = await Promise.race([probe(target.url, sampleController.signal), timeoutPromise]);
        kind = "success";
        durationMs = result.durationMs;
        httpStatus = result.httpStatus;
      } catch (err) {
        if (!running) break; // user stop: drop the in-flight event (D-3=A)
        if (timedOut) { kind = "timeout"; }
        else if (err instanceof ProbeError) { kind = err.kind; httpStatus = err.httpStatus; }
        else { kind = "network_error"; }
      } finally {
        if (timer) clearTimeout(timer);
        controller.signal.removeEventListener("abort", abortParent);
      }

      events.push(Core.createEvent({
        sessionId: session.id,
        sequence: i + 1,
        source: "browser",
        method: "http_get",
        targetId: cfg.targetId,
        targetUrl: target.url,
        timeoutMs: cfg.timeoutMs,
        profile: cfg.profile,
        config: session.config,
        kind: kind,
        httpStatus: httpStatus,
        durationMs: durationMs,
        stopReason: "completed"
      }));

      setProgress(events.length, cfg.samples);
      renderMetrics();
      updateChart();
      renderEvents();

      if (i < cfg.samples - 1 && running) await sleep(cfg.intervalMs);
    }

    var wasStopped = !running;
    running = false;
    session.stop_reason = wasStopped ? "stopped" : "completed";
    controller = null;

    events = Core.withStopReason(events, session.stop_reason);

    $("runBtn").disabled = false;
    $("stopBtn").disabled = true;
    $("profile").disabled = false;
    $("target").disabled = false;
    $("sampleCountInput").disabled = false;
    $("timeoutInput").disabled = false;
    $("intervalInput").disabled = false;

    renderMetrics();

    if (events.length) {
      $("progressText").textContent = wasStopped ? "Test stopped early" : "Test finished";
      setStatus(wasStopped ? "Test stopped" : "Test complete");
      saveHistory();
      setExportEnabled(true);
    } else {
      $("progressText").textContent = "No samples completed";
      setStatus("Ready to test");
      setExportEnabled(false);
    }

    updateSessionDetails();
  }

  function stopTest() {
    if (!running) return;
    running = false;
    if (controller) controller.abort();
    $("progressText").textContent = "Stopping\u2026";
  }

  /* ----- local history (summaries only, cap 8) ----- */
  function loadHistory() {
    try {
      var parsed = JSON.parse(localStorage.getItem("netscope-history") || "[]");
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) { return []; }
  }

  function saveHistory() {
    var stats = Core.computeStats(events);
    var item = Core.sessionSummary({
      profile: session.profile,
      targetId: session.target_id,
      targetName: session.target_name,
      attempted: stats.attempted,
      successful: stats.successful,
      failureRate: stats.failureRate,
      avg: stats.avg,
      stopReason: session.stop_reason
    });
    var history = [item].concat(loadHistory()).slice(0, 8);
    try { localStorage.setItem("netscope-history", JSON.stringify(history)); }
    catch (e) {
      $("noticeText").textContent = "Could not save this session locally (storage unavailable or full). Results are still shown.";
      $("notice").setAttribute("role", "alert");
      $("notice").hidden = false;
    }
    renderHistory();
  }

  function renderHistory() {
    var history = loadHistory();
    var list = $("historyList");
    if (!history.length) { list.innerHTML = '<div class="empty-history">No sessions saved yet.</div>'; return; }
    list.innerHTML = history.map(function (item) {
      var date = new Date(item.date);
      var dateText = Number.isNaN(date.getTime()) ? "Unknown date" : date.toLocaleString();
      var fail = Number.isFinite(item.failureRate) ? Math.round(item.failureRate * 100) + "%" : "\u2014";
      var ok = Number.isFinite(item.successful) ? item.successful : "\u2014";
      var attempts = Number.isFinite(item.attempted) ? item.attempted : "\u2014";
      var avgText = Number.isFinite(item.avg) ? item.avg + " ms" : "\u2014";
      return '<div class="history-item"><div><strong>' + escapeHtml(item.target_name || "Unknown target") +
        "</strong><small>" + escapeHtml(dateText) + " \u00b7 " + escapeHtml(item.profile || "") +
        " \u00b7 " + ok + "/" + attempts + " ok \u00b7 " + fail + " failed</small></div>" +
        '<div class="history-score">' + avgText + "</div></div>";
    }).join("");
  }

  /* ----- export ----- */
  function timestampSlug() { return new Date().toISOString().replace(/[:.]/g, "-"); }

  function download(filename, text, mime) {
    var blob = new Blob([text], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // Defer revoke: some browsers abort the download if the blob URL is
    // released in the same task as the synthetic click.
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  }

  function exportJSON() {
    if (!events.length) return;
    download("netscope-session-" + timestampSlug() + ".json", Core.buildExportJSON(events), "application/json");
  }

  function exportCSV() {
    if (!events.length) return;
    download("netscope-session-" + timestampSlug() + ".csv", Core.buildExportCSV(events), "text/csv");
  }

  /* ----- wiring ----- */
  $("runBtn").addEventListener("click", runTest);
  $("stopBtn").addEventListener("click", stopTest);
  $("profile").addEventListener("change", applyProfileDefaults);
  $("filterMethod").addEventListener("change", renderEvents);
  $("filterSource").addEventListener("change", renderEvents);
  $("exportJson").addEventListener("click", exportJSON);
  $("exportCsv").addEventListener("click", exportCSV);
  $("clearHistory").addEventListener("click", function () {
    try { localStorage.removeItem("netscope-history"); } catch (e) {}
    renderHistory();
  });

  /* ----- progressive disclosure (docs/10 §3.5) ----- */
  var evidenceToggle = $("evidenceToggle");
  if (evidenceToggle) {
    evidenceToggle.addEventListener("click", function () {
      var expanded = evidenceToggle.getAttribute("aria-expanded") === "true";
      evidenceToggle.setAttribute("aria-expanded", String(!expanded));
      $("evidenceBody").hidden = expanded;
      evidenceToggle.textContent = expanded ? "Show raw events" : "Hide raw events";
    });
  }

  /* ----- nav active state (scrollspy, no library) ----- */
  (function initScrollspy() {
    var links = Array.prototype.slice.call(document.querySelectorAll(".nav[data-section]"));
    if (!links.length) return;
    var sections = links.map(function (a) {
      return { id: a.getAttribute("data-section"), el: document.getElementById(a.getAttribute("data-section")) };
    }).filter(function (s) { return s.el; });
    if (!sections.length) return;

    function activeId() {
      var y = window.innerHeight * 0.35;
      var current = sections[0].id;
      // Last section whose top has crossed the reference line wins; this picks
      // the innermost visible section without relying on #main (a wrapper).
      for (var i = 0; i < sections.length; i++) {
        if (sections[i].el.getBoundingClientRect().top <= y) current = sections[i].id;
      }
      return current;
    }
    function apply() {
      var id = activeId();
      links.forEach(function (a) {
        a.classList.toggle("active", a.getAttribute("data-section") === id);
      });
    }
    var ticking = false;
    window.addEventListener("scroll", function () {
      if (ticking) return;
      ticking = true;
      (window.requestAnimationFrame || function (fn) { fn(); })(function () { apply(); ticking = false; });
    }, { passive: true });
    apply();
  })();

  initChart();
  renderHistory();
  renderMetrics();
  renderEvents();
  updateSessionDetails();
})();

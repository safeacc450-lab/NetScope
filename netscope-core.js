/*
 * NetScope core — pure, dependency-free logic for the Web MVP.
 *
 * Loaded in the browser via <script src="netscope-core.js"> (exposes
 * `window.NetScopeCore`) and in Node via `require("../netscope-core.js")` for
 * deterministic tests. Contains NO DOM and NO network access.
 *
 * Contract sources: docs/03-DATA-SCHEMA.md, docs/04-MEASUREMENT-METRICS.md,
 * docs/decisions/ADR-003-sample-count-and-percentiles.md, docs/05 §6 (D-1=B).
 */
(function (root, factory) {
  "use strict";
  var api = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (root) root.NetScopeCore = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  // PROVISIONAL / NOT FINAL (docs/03 §5, D-4). Do not treat as frozen.
  var SCHEMA_VERSION = 1;

  // Percentile display gate: profile-gated; only >= 20 valid completed samples
  // may show median/p95 (ADR-003). Quick Check default (12) never reaches it.
  var PERCENTILE_MIN_VALID = 20;

  var CSV_COLUMNS = [
    "schema_version",
    "event_id",
    "session_id",
    "sequence",
    "timestamp_utc",
    "source",
    "method",
    "target_id",
    "outcome",
    "error_kind",
    "http_status",
    "duration_ms",
    "timeout_ms",
    "profile",
    "config",
    "stop_reason",
    "target_url"
  ];

  // error_kind values the browser MUST NEVER emit (docs/03 §3, D-2=A):
  // CORS is not reliably distinguishable; DNS/TCP/TLS require backend/Android.
  var BROWSER_FORBIDDEN_ERROR_KINDS = ["cors", "dns", "tcp_refused", "tls"];

  var STOP_REASONS = ["completed", "stopped", "error"];

  function isFiniteNumber(v) {
    return typeof v === "number" && Number.isFinite(v);
  }

  /* ------------------------------------------------------------------ *
   * Percentiles — nearest-rank (ADR-003, one-based, no interpolation)
   * ------------------------------------------------------------------ */
  function percentileNearestRank(values, p) {
    if (!Array.isArray(values) || values.length === 0) return null;
    var sorted = values.slice().sort(function (a, b) { return a - b; });
    var r = Math.ceil(p * sorted.length); // one-based rank
    var idx = Math.min(Math.max(r, 1), sorted.length) - 1;
    return sorted[idx];
  }

  function validDurations(events) {
    return (events || [])
      .filter(function (e) {
        return e.outcome === "success" && isFiniteNumber(e.duration_ms);
      })
      .map(function (e) { return e.duration_ms; });
  }

  // Constrained-precision rounding (avoid 0.30000004 style artifacts).
  function round(value) {
    return Math.round(value * 1000) / 1000;
  }

  /* ------------------------------------------------------------------ *
   * Metrics — avg/min/max, jitter, failure rate, gated percentiles
   * (docs/04). Undefined values are `null`, never 0.
   * ------------------------------------------------------------------ */
  function computeStats(events) {
    var list = events || [];
    var durations = validDurations(list);
    var n = durations.length;
    var attempted = list.length;

    var stats = {
      source: "browser",
      attempted: attempted,
      successful: n,
      failed: 0,
      avg: null,
      min: null,
      max: null,
      median: null,
      p95: null,
      jitter: null,
      failureRate: null,
      percentileEligible: false,
      percentileReason: "percentiles require \u2265 " + PERCENTILE_MIN_VALID + " valid completed samples"
    };

    stats.failed = attempted - n;

    if (n > 0) {
      var sum = durations.reduce(function (a, b) { return a + b; }, 0);
      stats.avg = Math.round(sum / n);
      stats.min = Math.min.apply(null, durations);
      stats.max = Math.max.apply(null, durations);
    }

    if (n >= 2) {
      var diffs = [];
      for (var i = 1; i < durations.length; i++) {
        diffs.push(Math.abs(durations[i] - durations[i - 1]));
      }
      stats.jitter = Math.round(
        diffs.reduce(function (a, b) { return a + b; }, 0) / diffs.length
      );
    }

    if (attempted > 0) stats.failureRate = round(stats.failed / attempted);

    if (n >= PERCENTILE_MIN_VALID) {
      stats.percentileEligible = true;
      stats.median = percentileNearestRank(durations, 0.5);
      stats.p95 = percentileNearestRank(durations, 0.95);
      stats.percentileReason = null;
    }

    return stats;
  }

  /* ------------------------------------------------------------------ *
   * Error classification (docs/04 §6, docs/03 §2)
   * ------------------------------------------------------------------ */
  function classify(kind) {
    switch (kind) {
      case "success":
        return { outcome: "success", error_kind: null };
      case "timeout":
        return { outcome: "timeout", error_kind: "timeout" };
      case "http_error":
        return { outcome: "http_error", error_kind: "http_status" };
      case "unsupported":
        return { outcome: "unsupported", error_kind: null };
      case "blocked":
        return { outcome: "blocked", error_kind: null };
      case "network_error":
      case "ambiguous":
      default:
        // Browser `fetch` failure: cause not determinable (D-2=A).
        return { outcome: "network_error", error_kind: "ambiguous_network" };
    }
  }

  // Whether a given error_kind may be emitted by the browser platform.
  function isBrowserEmittableErrorKind(kind) {
    if (kind == null) return true; // null == no error / non-error outcome
    return BROWSER_FORBIDDEN_ERROR_KINDS.indexOf(kind) === -1;
  }

  /* ------------------------------------------------------------------ *
   * target_url privacy — option B (D-1=B, docs/05 §6)
   * Stored verbatim locally; query string + fragment stripped on export/sync.
   * ------------------------------------------------------------------ */
  function sanitizeTargetUrl(url) {
    if (url == null) return url;
    var raw = String(url);
    try {
      var u = new URL(raw);
      return u.protocol + "//" + u.host + u.pathname;
    } catch (e) {
      // Not an absolute URL: strip everything from the first ? or #.
      var cut = raw.search(/[?#]/);
      return cut === -1 ? raw : raw.slice(0, cut);
    }
  }

  /* ------------------------------------------------------------------ *
   * Event factory (docs/03)
   * ------------------------------------------------------------------ */
  function makeId(prefix) {
    var rand = Math.random().toString(16).slice(2, 10);
    return prefix + "_" + Date.now().toString(36) + "_" + rand;
  }

  function createEvent(input) {
    var c = classify(input.kind);
    return {
      schema_version: SCHEMA_VERSION,
      event_id: input.eventId || makeId("evt"),
      session_id: input.sessionId || null,
      sequence: input.sequence,
      timestamp_utc: input.timestampUtc || new Date().toISOString(),
      source: input.source || "browser",
      method: input.method || "http_get",
      target_id: input.targetId != null ? input.targetId : null,
      outcome: c.outcome,
      error_kind: c.error_kind,
      http_status: isFiniteNumber(input.httpStatus) ? input.httpStatus : null,
      duration_ms: isFiniteNumber(input.durationMs) ? input.durationMs : null,
      timeout_ms: isFiniteNumber(input.timeoutMs) ? input.timeoutMs : null,
      profile: input.profile != null ? input.profile : null,
      config: input.config || null,
      stop_reason: STOP_REASONS.indexOf(input.stopReason) !== -1 ? input.stopReason : "completed",
      target_url: input.targetUrl != null ? input.targetUrl : null
    };
  }

  // Stamp the final session stop_reason onto every event before export/save.
  function withStopReason(events, stopReason) {
    var value = STOP_REASONS.indexOf(stopReason) !== -1 ? stopReason : "error";
    return (events || []).map(function (e) {
      var clone = {};
      for (var k in e) if (Object.prototype.hasOwnProperty.call(e, k)) clone[k] = e[k];
      clone.stop_reason = value;
      return clone;
    });
  }

  /* ------------------------------------------------------------------ *
   * Export — JSON wrapper {schema_version, events} (docs/02 §F6)
   * ------------------------------------------------------------------ */
  function eventForExport(e) {
    var clone = {};
    for (var k in e) if (Object.prototype.hasOwnProperty.call(e, k)) clone[k] = e[k];
    clone.target_url = sanitizeTargetUrl(e.target_url);
    return clone;
  }

  function buildExportObject(events) {
    return {
      schema_version: SCHEMA_VERSION,
      events: (events || []).map(eventForExport)
    };
  }

  function buildExportJSON(events) {
    return JSON.stringify(buildExportObject(events), null, 2);
  }

  // Import tolerates unknown optional fields (additive-only, docs/03 §5).
  function parseImportedEvents(json) {
    var parsed = typeof json === "string" ? JSON.parse(json) : json;
    var events = Array.isArray(parsed) ? parsed : parsed && parsed.events;
    if (!Array.isArray(events)) throw new Error("Import: no events array found");
    return events; // unknown fields preserved as-is
  }

  /* ------------------------------------------------------------------ *
   * CSV — RFC 4180 quoting (docs/02 §F6)
   * ------------------------------------------------------------------ */
  function csvEscape(value) {
    if (value == null) return "";
    var s = String(value);
    // Spreadsheet formula-injection guard (OWASP CSV injection): neutralize a
    // leading = + - @ TAB CR in STRING cells with an apostrophe. Numeric cells
    // are left intact so negative numbers stay numeric.
    if (typeof value === "string" && /^[=+\-@\t\r]/.test(s)) s = "'" + s;
    if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }

  function buildExportCSV(events) {
    var rows = [(CSV_COLUMNS.join(","))];
    (events || []).forEach(function (raw) {
      var e = eventForExport(raw);
      rows.push(CSV_COLUMNS.map(function (col) {
        var v = e[col];
        if (v != null && typeof v === "object") v = JSON.stringify(v);
        return csvEscape(v);
      }).join(","));
    });
    return rows.join("\r\n");
  }

  /* ------------------------------------------------------------------ *
   * Session summary for local history (docs/02 §F5)
   * ------------------------------------------------------------------ */
  function sessionSummary(summary) {
    return {
      date: summary.date || new Date().toISOString(),
      profile: summary.profile || null,
      target_id: summary.targetId || null,
      target_name: summary.targetName || null,
      attempted: summary.attempted || 0,
      successful: summary.successful || 0,
      failureRate: summary.failureRate == null ? null : summary.failureRate,
      avg: summary.avg == null ? null : summary.avg,
      stop_reason: STOP_REASONS.indexOf(summary.stopReason) !== -1 ? summary.stopReason : "error"
    };
  }

  return {
    SCHEMA_VERSION: SCHEMA_VERSION,
    PERCENTILE_MIN_VALID: PERCENTILE_MIN_VALID,
    CSV_COLUMNS: CSV_COLUMNS,
    BROWSER_FORBIDDEN_ERROR_KINDS: BROWSER_FORBIDDEN_ERROR_KINDS,
    STOP_REASONS: STOP_REASONS,
    percentileNearestRank: percentileNearestRank,
    validDurations: validDurations,
    computeStats: computeStats,
    classify: classify,
    isBrowserEmittableErrorKind: isBrowserEmittableErrorKind,
    sanitizeTargetUrl: sanitizeTargetUrl,
    makeId: makeId,
    createEvent: createEvent,
    withStopReason: withStopReason,
    buildExportObject: buildExportObject,
    buildExportJSON: buildExportJSON,
    parseImportedEvents: parseImportedEvents,
    csvEscape: csvEscape,
    buildExportCSV: buildExportCSV,
    sessionSummary: sessionSummary
  };
});

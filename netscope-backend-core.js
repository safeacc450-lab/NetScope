/*
 * NetScope backend core — pure, dependency-free logic for the managed probe
 * backend contract. NO DOM, NO network, NO database.
 *
 * Status: PROVISIONAL. No HTTP server, provider, DB, or region is implemented
 * or decided here. See docs/11-BACKEND-API.md and PROJECT.md.
 *
 * Loaded in Node via `require("../netscope-backend-core.js")` for deterministic
 * tests; reuses `netscope-core.js` (which it requires in Node, or reads from
 * `root.NetScopeCore` in the browser).
 */
(function (root, factory) {
  "use strict";
  var core = null;
  if (typeof module !== "undefined" && module.exports) {
    try { core = require("./netscope-core.js"); } catch (e) { core = null; }
  }
  if (!core && root && root.NetScopeCore) core = root.NetScopeCore;
  var api = factory(core);
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (root) root.NetScopeBackendCore = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (core) {
  "use strict";

  // PROVISIONAL / NOT FINAL (docs/03 §5). Mirrors the browser core's value.
  var SCHEMA_VERSION = core && core.SCHEMA_VERSION != null ? core.SCHEMA_VERSION : 1;

  var BACKEND_SOURCE = "backend_probe";

  // Enums owned by docs/03 §2 (values PROVISIONAL).
  var SOURCES = ["browser", "backend_probe", "android_native"];
  var METHODS = ["http_get", "http_head", "icmp_echo", "dns_lookup", "tcp_connect", "tls_handshake"];
  var OUTCOMES = ["success", "timeout", "http_error", "network_error", "blocked", "unsupported"];
  var ERROR_KINDS = ["timeout", "http_status", "ambiguous_network", "cors", "dns", "tcp_refused", "tls"];
  var STOP_REASONS = core && core.STOP_REASONS ? core.STOP_REASONS : ["completed", "stopped", "error"];

  // Methods a serverless runtime must NOT claim (docs/06 §3): raw sockets/ICMP.
  var RAW_SOCKET_METHODS = ["icmp_echo", "dns_lookup", "tcp_connect", "tls_handshake"];

  var DEFAULT_TIMEOUT_MS = 1500; // PROVISIONAL example (docs/02 §B)
  var MAX_REDIRECTS = 5;

  function isPosInt(v) { return typeof v === "number" && Number.isInteger(v) && v > 0; }
  function isNonNegNumber(v) { return typeof v === "number" && isFinite(v) && v >= 0; }

  function makeId(prefix) {
    if (core && core.makeId) return core.makeId(prefix);
    return prefix + "_" + Date.now().toString(36) + "_" + Math.random().toString(16).slice(2, 10);
  }

  /* ------------------------------------------------------------------ *
   * SSRF — IP range classification (docs/05 §1)
   * ------------------------------------------------------------------ */
  function parseIpv4(ip) {
    if (typeof ip !== "string") return null;
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
    if (!m) return null;
    var out = [];
    for (var i = 1; i <= 4; i++) {
      var n = Number(m[i]);
      if (n > 255) return null;
      out.push(n);
    }
    return out;
  }

  function isDisallowedIpv4(a) {
    if (a[0] === 0) return true;                                   // 0.0.0.0/8
    if (a[0] === 10) return true;                                  // 10/8
    if (a[0] === 100 && a[1] >= 64 && a[1] <= 127) return true;    // 100.64/10 CGNAT
    if (a[0] === 127) return true;                                 // 127/8 loopback
    if (a[0] === 169 && a[1] === 254) return true;                 // 169.254/16 link-local + metadata
    if (a[0] === 172 && a[1] >= 16 && a[1] <= 31) return true;     // 172.16/12
    if (a[0] === 192 && a[1] === 0 && a[2] === 0) return true;     // 192.0.0/24
    if (a[0] === 192 && a[1] === 0 && a[2] === 2) return true;     // 192.0.2/24 TEST-NET-1
    if (a[0] === 192 && a[1] === 168) return true;                 // 192.168/16
    if (a[0] === 198 && (a[1] === 18 || a[1] === 19)) return true; // 198.18/15
    if (a[0] === 198 && a[1] === 51 && a[2] === 100) return true;  // 198.51.100/24 TEST-NET-2
    if (a[0] === 203 && a[1] === 0 && a[2] === 113) return true;   // 203.0.113/24 TEST-NET-3
    if (a[0] >= 224) return true;                                  // 224/4 multicast + 240/4 reserved
    return false;
  }

  function isDisallowedIpv6(ip) {
    var s = String(ip).toLowerCase();
    var zone = s.indexOf("%");
    if (zone !== -1) s = s.slice(0, zone);
    if (s.charAt(0) === "[" && s.charAt(s.length - 1) === "]") s = s.slice(1, -1);
    if (s === "::1" || s === "::") return true;                    // loopback / unspecified
    if (/^fe[89ab]/.test(s)) return true;                          // fe80::/10 link-local
    if (/^f[cd]/.test(s)) return true;                             // fc00::/7 unique-local
    if (/^ff/.test(s)) return true;                                // ff00::/8 multicast
    var m = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s); // IPv4-mapped
    if (m) { var v4 = parseIpv4(m[1]); return v4 ? isDisallowedIpv4(v4) : true; }
    m = /^::(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);          // IPv4-compatible (deprecated)
    if (m) { var v42 = parseIpv4(m[1]); return v42 ? isDisallowedIpv4(v42) : true; }
    return false;
  }

  // True for private/loopback/link-local/metadata/reserved addresses.
  // Hostnames (not IP literals) return false; they must be resolved and pinned
  // by the transport, then re-checked (docs/05 §1, not implemented here).
  function isDisallowedIp(ip) {
    var v4 = parseIpv4(ip);
    if (v4) return isDisallowedIpv4(v4);
    if (typeof ip === "string" && ip.indexOf(":") !== -1) return isDisallowedIpv6(ip);
    return false;
  }

  function isIpLiteral(host) {
    return parseIpv4(host) != null || (typeof host === "string" && host.indexOf(":") !== -1);
  }

  /* ------------------------------------------------------------------ *
   * URL / target validation
   * ------------------------------------------------------------------ */
  function parseHttpUrl(raw, opts) {
    opts = opts || {};
    var u;
    try { u = new URL(String(raw)); } catch (e) {
      return { ok: false, code: "invalid_target", message: "not a valid absolute URL" };
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      return { ok: false, code: "invalid_target", message: "scheme must be http or https" };
    }
    if (u.username || u.password) {
      return { ok: false, code: "invalid_target", message: "userinfo is not allowed" };
    }
    if (u.hash) {
      return { ok: false, code: "invalid_target", message: "fragment is not allowed" };
    }
    if (!u.hostname) {
      return { ok: false, code: "invalid_target", message: "host is required" };
    }
    var host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    // allowPrivate is a TEST/DEV-ONLY escape hatch (default false = block). It
    // must never be enabled in a deployed allow-list (docs/05 §1).
    if (!opts.allowPrivate && isIpLiteral(host) && isDisallowedIp(host)) {
      return { ok: false, code: "invalid_target", message: "private/link-local/metadata IP is not allowed" };
    }
    return { ok: true, code: null, message: null, host: host, url: u };
  }

  // PROVISIONAL registry shape (format is OPEN in PROJECT.md). Throws on a
  // malformed entry so a bad allow-list fails loudly rather than silently.
  function createRegistry(entries, opts) {
    opts = opts || {};
    var allowPrivate = opts.allowPrivate === true;
    entries = entries || [];
    var byId = {};
    var hostSet = {};
    var list = [];

    entries.forEach(function (entry, i) {
      if (!entry || typeof entry.target_id !== "string" || !entry.target_id) {
        throw new Error("registry[" + i + "]: target_id required");
      }
      if (byId[entry.target_id]) {
        throw new Error("registry[" + i + "]: duplicate target_id " + entry.target_id);
      }
      var parsed = parseHttpUrl(entry.url, { allowPrivate: allowPrivate });
      if (!parsed.ok) {
        throw new Error("registry[" + i + "] (" + entry.target_id + "): " + parsed.message);
      }
      var methods = Array.isArray(entry.methods) ? entry.methods.slice() : METHODS.slice();
      methods.forEach(function (m) {
        if (METHODS.indexOf(m) === -1) {
          throw new Error("registry[" + i + "] (" + entry.target_id + "): unknown method " + m);
        }
      });
      var norm = { target_id: entry.target_id, url: parsed.url.href, host: parsed.host, methods: methods };
      byId[entry.target_id] = norm;
      hostSet[parsed.host] = true;
      list.push(norm);
    });

    return {
      entries: list,
      allowPrivate: allowPrivate,
      get: function (id) { return Object.prototype.hasOwnProperty.call(byId, id) ? byId[id] : null; },
      hasHost: function (h) { return Object.prototype.hasOwnProperty.call(hostSet, String(h).toLowerCase()); },
      hosts: function () { return Object.keys(hostSet); }
    };
  }

  function validateProbeRequest(request, registry) {
    request = request || {};
    registry = registry || createRegistry([]);
    var errors = [];

    var entry = null;
    if (typeof request.target_id !== "string" || !request.target_id) {
      errors.push({ field: "target_id", code: "invalid_target", message: "target_id is required" });
    } else {
      entry = registry.get(request.target_id);
      if (!entry) errors.push({ field: "target_id", code: "invalid_target", message: "target is not in the allow-list" });
    }

    var method = request.method == null ? "http_get" : request.method;
    if (METHODS.indexOf(method) === -1) {
      errors.push({ field: "method", code: "invalid_method", message: "method is not a schema method" });
    } else if (entry && entry.methods.indexOf(method) === -1) {
      errors.push({ field: "method", code: "invalid_method", message: "method is not allowed for this target" });
    }

    var timeout = DEFAULT_TIMEOUT_MS;
    if (request.timeout_ms != null) {
      if (isPosInt(request.timeout_ms)) timeout = request.timeout_ms;
      else errors.push({ field: "timeout_ms", code: "invalid_timeout", message: "timeout_ms must be a positive integer" });
    }

    if (errors.length) return { ok: false, errors: errors };

    return {
      ok: true,
      errors: [],
      request: {
        request_id: request.request_id != null ? request.request_id : null,
        client_id: request.client_id != null ? request.client_id : null,
        target_id: entry.target_id,
        url: entry.url,
        host: entry.host,
        method: method,
        timeout_ms: timeout,
        profile: request.profile != null ? request.profile : null
      }
    };
  }

  // Validate one redirect hop: cap count, http(s), no userinfo/fragment, host in
  // the registry allow-list (docs/05 §1 "validate every redirect hop").
  function validateRedirect(hopUrl, registry, hopIndex, maxHops) {
    registry = registry || createRegistry([]);
    maxHops = maxHops == null ? MAX_REDIRECTS : maxHops;
    if (typeof hopIndex !== "number" || hopIndex < 0) hopIndex = 0;
    if (hopIndex >= maxHops) {
      return { ok: false, code: "redirect_limit", message: "too many redirects (max " + maxHops + ")" };
    }
    var parsed = parseHttpUrl(hopUrl, { allowPrivate: registry.allowPrivate === true });
    if (!parsed.ok) {
      return { ok: false, code: "redirect_not_allowed", message: parsed.message };
    }
    if (!registry.hasHost(parsed.host)) {
      return { ok: false, code: "redirect_not_allowed", message: "redirect host not in allow-list: " + parsed.host };
    }
    return { ok: true, code: null, message: null, host: parsed.host, url: parsed.url.href };
  }

  /* ------------------------------------------------------------------ *
   * Error classification for backend_probe (docs/03 §3, docs/04 §6)
   * The backend MAY emit dns/tcp_refused/tls/cors when directly observed.
   * ------------------------------------------------------------------ */
  function classifyBackend(kind) {
    switch (kind) {
      case "success": return { outcome: "success", error_kind: null };
      case "timeout": return { outcome: "timeout", error_kind: "timeout" };
      case "http_error": return { outcome: "http_error", error_kind: "http_status" };
      case "dns": return { outcome: "network_error", error_kind: "dns" };
      case "tcp_refused": return { outcome: "network_error", error_kind: "tcp_refused" };
      case "tls": return { outcome: "network_error", error_kind: "tls" };
      case "cors": return { outcome: "network_error", error_kind: "cors" };
      case "blocked": return { outcome: "blocked", error_kind: null };
      case "unsupported": return { outcome: "unsupported", error_kind: null };
      case "network_error":
      case "ambiguous":
      default:
        return { outcome: "network_error", error_kind: "ambiguous_network" };
    }
  }

  /* ------------------------------------------------------------------ *
   * Event factory — always source = backend_probe (docs/01 §2)
   * ------------------------------------------------------------------ */
  function createBackendEvent(input) {
    input = input || {};
    var c = classifyBackend(input.kind);
    return {
      schema_version: SCHEMA_VERSION,
      event_id: input.eventId || makeId("evt"),
      session_id: input.sessionId != null ? input.sessionId : null,
      sequence: input.sequence,
      timestamp_utc: input.timestampUtc || new Date().toISOString(),
      source: BACKEND_SOURCE,
      method: METHODS.indexOf(input.method) !== -1 ? input.method : "http_get",
      target_id: input.targetId != null ? input.targetId : null,
      outcome: c.outcome,
      error_kind: c.error_kind,
      http_status: Number.isInteger(input.httpStatus) ? input.httpStatus : null,
      duration_ms: isNonNegNumber(input.durationMs) ? input.durationMs : null,
      timeout_ms: isPosInt(input.timeoutMs) ? input.timeoutMs : null,
      profile: input.profile != null ? input.profile : null,
      config: input.config || null,
      stop_reason: STOP_REASONS.indexOf(input.stopReason) !== -1 ? input.stopReason : "completed",
      target_url: input.targetUrl != null ? input.targetUrl : null
    };
  }

  function finalizeEvents(events, stopReason) {
    if (core && core.withStopReason) return core.withStopReason(events, stopReason);
    var value = STOP_REASONS.indexOf(stopReason) !== -1 ? stopReason : "error";
    return (events || []).map(function (e) {
      var clone = {};
      for (var k in e) if (Object.prototype.hasOwnProperty.call(e, k)) clone[k] = e[k];
      clone.stop_reason = value;
      return clone;
    });
  }

  /* ------------------------------------------------------------------ *
   * Schema validation (docs/03)
   * ------------------------------------------------------------------ */
  function validateEvent(event) {
    var errors = [];
    if (!event || typeof event !== "object") {
      return { ok: false, errors: [{ code: "invalid_event", message: "event must be an object" }] };
    }
    function bad(field, message) { errors.push({ field: field, code: "invalid_event", message: message }); }

    if (!Number.isInteger(event.schema_version)) bad("schema_version", "must be an integer");
    if (typeof event.event_id !== "string" || !event.event_id) bad("event_id", "must be a non-empty string");
    if (!(typeof event.session_id === "string" || event.session_id === null)) bad("session_id", "must be a string or null");
    if (!Number.isInteger(event.sequence)) bad("sequence", "must be an integer");
    if (typeof event.timestamp_utc !== "string" || isNaN(Date.parse(event.timestamp_utc))) bad("timestamp_utc", "must be an ISO 8601 string");
    if (SOURCES.indexOf(event.source) === -1) bad("source", "unknown source");
    if (METHODS.indexOf(event.method) === -1) bad("method", "unknown method");
    if (OUTCOMES.indexOf(event.outcome) === -1) bad("outcome", "unknown outcome");

    if (event.outcome === "success") {
      if (event.error_kind !== null) bad("error_kind", "must be null when outcome is success");
    } else if (event.error_kind == null) {
      bad("error_kind", "is required when outcome is not success");
    } else if (ERROR_KINDS.indexOf(event.error_kind) === -1) {
      bad("error_kind", "unknown error_kind");
    }

    if (!(event.http_status === null || Number.isInteger(event.http_status))) bad("http_status", "must be an integer or null");
    if (!(event.duration_ms === null || isNonNegNumber(event.duration_ms))) bad("duration_ms", "must be a non-negative number or null");
    if (!isPosInt(event.timeout_ms)) bad("timeout_ms", "must be a positive integer");

    return { ok: errors.length === 0, errors: errors };
  }

  function validateBackendEvent(event) {
    var result = validateEvent(event);
    if (result.ok && event.source !== BACKEND_SOURCE) {
      return { ok: false, errors: [{ field: "source", code: "invalid_event", message: "backend event must have source=" + BACKEND_SOURCE }] };
    }
    return result;
  }

  /* ------------------------------------------------------------------ *
   * Rate limiting (docs/05 §1 abuse/flooding) — in-memory fixed window
   * ------------------------------------------------------------------ */
  function createRateLimiter(options) {
    options = options || {};
    var limit = isPosInt(options.limit) ? options.limit : 60;
    var windowMs = isPosInt(options.windowMs) ? options.windowMs : 60000;
    var now = typeof options.now === "function" ? options.now : function () { return Date.now(); };
    var buckets = {};

    return {
      check: function (key) {
        key = key == null ? "anonymous" : String(key);
        var t = now();
        var b = buckets[key];
        if (!b || t - b.windowStart >= windowMs) {
          b = { count: 0, windowStart: t };
          buckets[key] = b;
        }
        if (b.count >= limit) {
          return { allowed: false, remaining: 0, retryAfterMs: windowMs - (t - b.windowStart) };
        }
        b.count++;
        return { allowed: true, remaining: limit - b.count, retryAfterMs: 0 };
      },
      reset: function (key) {
        if (key == null) buckets = {};
        else delete buckets[String(key)];
      },
      limit: limit,
      windowMs: windowMs
    };
  }

  /* ------------------------------------------------------------------ *
   * Timeout vs user cancellation (D-3=A)
   * ------------------------------------------------------------------ */
  function sampleDisposition(state) {
    state = state || {};
    if (state.userStopped && !state.timedOut) {
      return { record: false, kind: null, stop_reason: "stopped" };
    }
    if (state.timedOut) return { record: true, kind: "timeout", stop_reason: "completed" };
    if (state.failed) return { record: true, kind: "network_error", stop_reason: "completed" };
    return { record: true, kind: "success", stop_reason: "completed" };
  }

  /* ------------------------------------------------------------------ *
   * In-memory storage interface (PROVISIONAL; DB provider is OPEN)
   * ------------------------------------------------------------------ */
  function createMemoryStore() {
    var sessions = {};
    return {
      saveSession: function (session) {
        if (!session || typeof session.session_id !== "string" || !session.session_id) {
          throw new Error("saveSession: session_id required");
        }
        sessions[session.session_id] = session;
        return session;
      },
      getSession: function (id) {
        return Object.prototype.hasOwnProperty.call(sessions, id) ? sessions[id] : null;
      },
      listSessions: function () {
        return Object.keys(sessions).map(function (k) { return sessions[k]; });
      },
      deleteSession: function (id) {
        if (!Object.prototype.hasOwnProperty.call(sessions, id)) return false;
        delete sessions[id];
        return true;
      },
      clear: function () { sessions = {}; }
    };
  }

  /* ------------------------------------------------------------------ *
   * Metrics — same math as browser, source relabeled (docs/04)
   * ------------------------------------------------------------------ */
  function summarize(events, source) {
    var stats = core && core.computeStats ? core.computeStats(events) : null;
    if (stats) stats.source = source || BACKEND_SOURCE;
    return stats;
  }

  return {
    SCHEMA_VERSION: SCHEMA_VERSION,
    BACKEND_SOURCE: BACKEND_SOURCE,
    SOURCES: SOURCES,
    METHODS: METHODS,
    OUTCOMES: OUTCOMES,
    ERROR_KINDS: ERROR_KINDS,
    RAW_SOCKET_METHODS: RAW_SOCKET_METHODS,
    DEFAULT_TIMEOUT_MS: DEFAULT_TIMEOUT_MS,
    MAX_REDIRECTS: MAX_REDIRECTS,
    parseIpv4: parseIpv4,
    isDisallowedIp: isDisallowedIp,
    isIpLiteral: isIpLiteral,
    parseHttpUrl: parseHttpUrl,
    createRegistry: createRegistry,
    validateProbeRequest: validateProbeRequest,
    validateRedirect: validateRedirect,
    classifyBackend: classifyBackend,
    createBackendEvent: createBackendEvent,
    finalizeEvents: finalizeEvents,
    validateEvent: validateEvent,
    validateBackendEvent: validateBackendEvent,
    createRateLimiter: createRateLimiter,
    sampleDisposition: sampleDisposition,
    createMemoryStore: createMemoryStore,
    summarize: summarize
  };
});

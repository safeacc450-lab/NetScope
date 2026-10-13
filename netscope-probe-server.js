/*
 * NetScope probe server — Node stdlib only (no framework, no dependencies).
 *
 * Status: PROVISIONAL. DEV-ONLY: no auth, no database, no provider, no region,
 * no TLS. Binds to 127.0.0.1 by default. Do NOT deploy. See docs/11-BACKEND-API.md.
 *
 * Creates a managed-probe HTTP API on top of netscope-backend-core.js. All
 * events carry source="backend_probe" and never a browser-origin cause.
 * Raw-socket methods (dns_lookup/tcp_connect/tls_handshake/icmp_echo) are
 * refused here; they require a raw-socket host (docs/06 §3) — not implemented.
 */
"use strict";

var http = require("node:http");
var dns = require("node:dns");
var backend = require("./netscope-backend-core.js");
var core = require("./netscope-core.js");

var MAX_BODY_BYTES = 8 * 1024;
var REDIRECT_STATUS = [301, 302, 303, 307, 308];

var monotonic = typeof performance !== "undefined" && performance.now
  ? function () { return performance.now(); }
  : function () { return Date.now(); };

function defaultResolveHost(host) {
  return new Promise(function (resolve, reject) {
    dns.lookup(host, function (err, address) {
      if (err) reject(err);
      else resolve(address);
    });
  });
}

/*
 * Default transport: real HTTP via global fetch, manual redirect handling so
 * every hop is validated against the allow-list, plus a resolve-then-check of
 * the target host. NOTE: this is a resolve-then-check, NOT a pinned connection;
 * true DNS-rebinding pinning is NOT implemented (docs/05 §1, still OPEN).
 */
async function defaultTransport(request, context) {
  var registry = context.registry;
  var resolveHost = context.resolveHost || defaultResolveHost;
  var start = monotonic();
  var controller = new AbortController();
  var timedOut = false;
  var timer = setTimeout(function () { timedOut = true; controller.abort(); }, request.timeout_ms);

  try {
    var current = request.url;
    var hop = 0;
    for (;;) {
      var host = new URL(current).hostname.replace(/^\[|\]$/g, "");
      if (!registry.allowPrivate) {
        var ip;
        try {
          ip = await resolveHost(host);
        } catch (e) {
          return { kind: "dns", durationMs: null, httpStatus: null, finalUrl: current };
        }
        if (backend.isDisallowedIp(ip)) {
          return { kind: "blocked", durationMs: null, httpStatus: null, finalUrl: current };
        }
      }

      var res = await fetch(current, {
        method: request.method === "http_head" ? "HEAD" : "GET",
        redirect: "manual",
        cache: "no-store",
        signal: controller.signal
      });

      if (REDIRECT_STATUS.indexOf(res.status) !== -1) {
        var location = res.headers.get("location");
        if (!location) {
          return { kind: "http_error", httpStatus: res.status, durationMs: Math.round(monotonic() - start), finalUrl: current };
        }
        var next = new URL(location, current).href;
        var check = backend.validateRedirect(next, registry, hop, backend.MAX_REDIRECTS);
        if (!check.ok) {
          return { kind: "blocked", httpStatus: res.status, durationMs: Math.round(monotonic() - start), finalUrl: current, note: check.code };
        }
        current = next;
        hop++;
        continue;
      }

      var duration = Math.round(monotonic() - start);
      if (res.status >= 200 && res.status < 300) {
        return { kind: "success", httpStatus: res.status, durationMs: duration, finalUrl: current };
      }
      return { kind: "http_error", httpStatus: res.status, durationMs: duration, finalUrl: current };
    }
  } catch (err) {
    if (timedOut) return { kind: "timeout", durationMs: null, httpStatus: null, finalUrl: request.url };
    return { kind: "network_error", durationMs: null, httpStatus: null, finalUrl: request.url };
  } finally {
    clearTimeout(timer);
  }
}

function readBody(req, limit) {
  return new Promise(function (resolve, reject) {
    var chunks = [];
    var size = 0;
    req.on("data", function (chunk) {
      if (size > limit) return; // already rejected; keep draining the socket
      size += chunk.length;
      if (size > limit) {
        var err = new Error("payload too large");
        err.code = "payload_too_large";
        reject(err); // do NOT req.destroy(): let the 413 response reach the client
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", function () { resolve(Buffer.concat(chunks).toString("utf8")); });
    req.on("error", reject);
  });
}

function sendJson(res, status, payload, extraHeaders) {
  var body = JSON.stringify(payload);
  var headers = { "Content-Type": "application/json; charset=utf-8" };
  if (extraHeaders) for (var k in extraHeaders) if (Object.prototype.hasOwnProperty.call(extraHeaders, k)) headers[k] = extraHeaders[k];
  res.writeHead(status, headers);
  res.end(body);
}

function sendError(res, status, code, message) {
  sendJson(res, status, { error: { code: code, message: message } });
}

function createProbeServer(options) {
  options = options || {};

  var registry = options.registry && typeof options.registry.get === "function"
    ? options.registry
    : backend.createRegistry(options.registry || [], { allowPrivate: options.allowPrivate === true });

  var store = options.store || backend.createMemoryStore();
  var transport = options.transport || defaultTransport;
  var resolveHost = options.resolveHost || defaultResolveHost;
  var maxBodyBytes = options.maxBodyBytes || MAX_BODY_BYTES;
  var corsOrigin = options.corsOrigin || null; // OPEN decision; default: no CORS
  var rateLimiter = options.rateLimiter || backend.createRateLimiter({
    limit: options.rateLimit || 60,
    windowMs: options.rateWindowMs || 60000
  });

  function corsHeaders() {
    return corsOrigin ? { "Access-Control-Allow-Origin": corsOrigin, "Access-Control-Allow-Headers": "content-type", "Access-Control-Allow-Methods": "GET,POST,OPTIONS" } : null;
  }

  async function handleProbe(req, res) {
    var raw;
    try {
      raw = await readBody(req, maxBodyBytes);
    } catch (e) {
      if (e && e.code === "payload_too_large") return sendError(res, 413, "payload_too_large", "request body too large");
      return sendError(res, 400, "invalid_request", "could not read request body");
    }

    var body;
    try {
      body = raw ? JSON.parse(raw) : {};
    } catch (e) {
      return sendError(res, 400, "invalid_request", "body must be valid JSON");
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return sendError(res, 400, "invalid_request", "body must be a JSON object");
    }

    // Raw-socket methods need a raw-socket host; refuse them at this server.
    if (body.method && backend.RAW_SOCKET_METHODS.indexOf(body.method) !== -1) {
      return sendError(res, 400, "invalid_method", "raw-socket methods require a raw-socket host (not implemented)");
    }

    var clientKey = (typeof body.client_id === "string" && body.client_id) ? body.client_id : (req.socket.remoteAddress || "anonymous");
    var rl = rateLimiter.check(clientKey);
    if (!rl.allowed) {
      res.setHeader("Retry-After", String(Math.max(1, Math.ceil(rl.retryAfterMs / 1000))));
      return sendJson(res, 429, { error: { code: "rate_limited", message: "rate limit exceeded" }, retry_after_ms: rl.retryAfterMs }, corsHeaders());
    }

    var v = backend.validateProbeRequest(body, registry);
    if (!v.ok) {
      return sendJson(res, 400, {
        error: { code: v.errors[0].code, message: v.errors.map(function (e) { return e.field + ": " + e.message; }).join("; ") },
        errors: v.errors
      }, corsHeaders());
    }

    var request = v.request;
    var sessionId = core.makeId("session");

    var outcome;
    try {
      outcome = await transport(request, { registry: registry, resolveHost: resolveHost, backend: backend });
    } catch (e) {
      return sendError(res, 502, "upstream_error", "probe transport failed");
    }

    var event = backend.createBackendEvent({
      sessionId: sessionId,
      sequence: 1,
      method: request.method,
      targetId: request.target_id,
      targetUrl: request.url,
      timeoutMs: request.timeout_ms,
      profile: request.profile,
      kind: outcome.kind,
      httpStatus: outcome.httpStatus != null ? outcome.httpStatus : null,
      durationMs: outcome.durationMs != null ? outcome.durationMs : null,
      stopReason: "completed"
    });
    var events = backend.finalizeEvents([event], "completed");

    var session = {
      session_id: sessionId,
      source: backend.BACKEND_SOURCE,
      profile: request.profile,
      target_id: request.target_id,
      target_url: request.url,
      stop_reason: "completed",
      config: { timeout_ms: request.timeout_ms },
      events: events
    };
    store.saveSession(session);

    return sendJson(res, 200, {
      schema_version: backend.SCHEMA_VERSION,
      source: backend.BACKEND_SOURCE,
      session_id: sessionId,
      target_id: request.target_id,
      events: events,
      summary: backend.summarize(events)
    }, corsHeaders());
  }

  async function handle(req, res) {
    var url = new URL(req.url, "http://localhost");

    if (req.method === "OPTIONS" && corsOrigin) {
      res.writeHead(204, corsHeaders() || {});
      return res.end();
    }
    if (req.method === "GET" && url.pathname === "/health") {
      return sendJson(res, 200, { ok: true, source: backend.BACKEND_SOURCE, schema_version: backend.SCHEMA_VERSION }, corsHeaders());
    }
    if (req.method === "GET" && url.pathname === "/api/targets") {
      var targets = registry.entries.map(function (e) { return { target_id: e.target_id, url: e.url, methods: e.methods }; });
      return sendJson(res, 200, { targets: targets }, corsHeaders());
    }
    if (req.method === "POST" && url.pathname === "/api/probe") {
      return handleProbe(req, res);
    }
    if (req.method === "GET" && url.pathname === "/api/sessions") {
      var sessions = store.listSessions().map(function (s) {
        var stats = backend.summarize(s.events);
        return { session_id: s.session_id, source: s.source, profile: s.profile, target_id: s.target_id, stop_reason: s.stop_reason, attempted: stats ? stats.attempted : null, successful: stats ? stats.successful : null };
      });
      return sendJson(res, 200, { sessions: sessions }, corsHeaders());
    }
    var m = /^\/api\/sessions\/([^/]+)$/.exec(url.pathname);
    if (req.method === "GET" && m) {
      var session = store.getSession(decodeURIComponent(m[1]));
      if (!session) return sendError(res, 404, "not_found", "session not found");
      return sendJson(res, 200, session, corsHeaders());
    }
    return sendError(res, 404, "not_found", "unknown route");
  }

  var server = http.createServer(function (req, res) {
    handle(req, res).catch(function () { sendError(res, 500, "internal_error", "unexpected server error"); });
  });
  server.store = store;
  server.registry = registry;
  return server;
}

function startServer(options, port, host) {
  var server = createProbeServer(options);
  port = port == null ? (process.env.PORT ? Number(process.env.PORT) : 8787) : port;
  host = host || "127.0.0.1";
  server.listen(port, host, function () {
    process.stdout.write("NetScope probe server (DEV-ONLY, no auth) on http://" + host + ":" + port + "\n");
  });
  return server;
}

module.exports = {
  createProbeServer: createProbeServer,
  startServer: startServer,
  defaultTransport: defaultTransport,
  defaultResolveHost: defaultResolveHost,
  MAX_BODY_BYTES: MAX_BODY_BYTES
};

if (require.main === module) {
  startServer({ registry: [], rateLimit: 30 });
}

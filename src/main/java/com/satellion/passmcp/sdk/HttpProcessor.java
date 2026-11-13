// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

/**
 * Pure Streamable HTTP server processor ({@code HttpRequest -> HttpResponse}) with an optional
 * {@link HttpHandler} adapter for {@code jdk.httpserver}.
 *
 * <p>Enforces {@link OriginGuard} ({@code 403}), optional RFC 9728 Bearer authentication
 * ({@code 401} + {@code WWW-Authenticate}), {@code POST}-only method gating ({@code 405}),
 * {@code 202 Accepted} notifications, {@code 400} parse errors, {@code 2026-07-28} mirrored
 * header agreement ({@code -32020}) and {@code 404} unknown-method mapping, plus optional
 * {@code Mcp-Session-Id} issuance and validation on session-era servers.
 */
public final class HttpProcessor {
    /** Immutable HTTP request value for transport-agnostic server processing. */
    public record HttpRequest(String method, String path, Map<String, String> headers, String body) {
        /** Normalizes fields on construction. */
        public HttpRequest {
            method = method == null ? "" : method;
            path = path == null ? "/" : path;
            headers = headers == null ? Map.of() : Map.copyOf(headers);
            body = body == null ? "" : body;
        }

        /** Case-insensitive header lookup. */
        public String header(String name) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if (e.getKey().equalsIgnoreCase(name)) {
                    return e.getValue();
                }
            }
            return null;
        }
    }

    /** Immutable HTTP response value returned by {@link HttpProcessor#handle(HttpRequest)}. */
    public record HttpResponse(int status, Map<String, String> headers, String body) {
        /** Normalizes fields on construction. */
        public HttpResponse {
            headers = headers == null ? Map.of() : Map.copyOf(headers);
            body = body == null ? "" : body;
        }

        /** Case-insensitive header lookup. */
        public String header(String name) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if (e.getKey().equalsIgnoreCase(name)) {
                    return e.getValue();
                }
            }
            return null;
        }
    }

    private final McpServer server;
    private Predicate<String> bearerValidator;
    private String resourceMetadataUrl;
    private boolean sessionsEnabled;
    private final Set<String> activeSessions = ConcurrentHashMap.newKeySet();

    /** Creates an HTTP processor fronting {@code server}. */
    public HttpProcessor(McpServer server) {
        this.server = Objects.requireNonNull(server, "server");
    }

    /** Configures Bearer token validation and the RFC 9728 {@code resource_metadata} challenge URL. */
    public HttpProcessor requireBearerAuth(Predicate<String> validator, String metadataUrl) {
        this.bearerValidator = Objects.requireNonNull(validator, "validator");
        this.resourceMetadataUrl = metadataUrl;
        return this;
    }

    /** Enables {@code Mcp-Session-Id} issuance on {@code initialize} and validation on later calls. */
    public HttpProcessor enableSessions(boolean enabled) {
        this.sessionsEnabled = enabled;
        return this;
    }

    /** Processes an incoming Streamable HTTP request without requiring a network socket. */
    public HttpResponse handle(HttpRequest request) {
        Objects.requireNonNull(request, "request");
        if (!server.originGuard().isAllowed(request.header("Origin"))) {
            return new HttpResponse(403, Map.of(), "");
        }
        HttpResponse authFailure = checkBearer(request);
        if (authFailure != null) {
            return authFailure;
        }
        if (!"POST".equalsIgnoreCase(request.method())) {
            return new HttpResponse(405, Map.of("Allow", "POST"), "");
        }
        return handlePost(request);
    }

    /** Adapts this processor to a standard JDK {@link HttpHandler}. */
    public HttpHandler toJdkHttpHandler() {
        return this::serveJdkExchange;
    }

    private HttpResponse checkBearer(HttpRequest request) {
        if (bearerValidator == null) {
            return null;
        }
        String auth = request.header("Authorization");
        String token = extractBearerToken(auth);
        if (token != null && bearerValidator.test(token)) {
            return null;
        }
        String challenge = OAuth.buildBearerChallenge(resourceMetadataUrl, null, null, null);
        return new HttpResponse(401, Map.of("WWW-Authenticate", challenge), "");
    }

    private HttpResponse handlePost(HttpRequest request) {
        Map<String, Object> env = tryParseRequestObject(request.body());
        if (env == null) {
            return parseFailureResponse(request.body());
        }
        Object id = extractJsonRpcId(env.get("id"));
        String method = env.get("method") instanceof String m ? m : "";
        HttpResponse mismatch = checkMirroredHeaders(request, env, id, method);
        if (mismatch != null) {
            return mismatch;
        }
        if (requiresExistingSession(method) && !isValidSession(request.header("Mcp-Session-Id"))) {
            return new HttpResponse(404, Map.of(), "");
        }
        return dispatchServerJson(request, method);
    }

    private HttpResponse dispatchServerJson(HttpRequest request, String method) {
        String reply = server.handleJson(request.body());
        if (reply.isEmpty()) {
            return new HttpResponse(202, Map.of(), "");
        }
        if (isStatelessRequest(request) && isErrorCode(reply, -32601)) {
            return jsonReply(404, reply);
        }
        return finalizeOk(method, reply);
    }

    private static Map<String, Object> tryParseRequestObject(String body) {
        try {
            Object parsed = Json.parse(body);
            return parsed instanceof Map<?, ?> ? Json.asObject(parsed, "request") : null;
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private static HttpResponse parseFailureResponse(String body) {
        try {
            Json.parse(body);
            return jsonReply(400, rpcErrorJson(null, -32600, "Invalid Request: expected JSON object"));
        } catch (IllegalArgumentException ex) {
            return jsonReply(400, rpcErrorJson(null, -32700, "Parse error: invalid JSON payload"));
        }
    }

    private static Object extractJsonRpcId(Object rawId) {
        return (rawId instanceof String || rawId instanceof Number) ? rawId : null;
    }

    private HttpResponse checkMirroredHeaders(
            HttpRequest request, Map<String, Object> env, Object id, String bodyMethod) {
        String hdrMethod = request.header("MCP-Method");
        boolean stateless = isStatelessRequest(request) || hdrMethod != null;
        if (!stateless) {
            return null;
        }
        if (hdrMethod != null && !hdrMethod.isEmpty() && !hdrMethod.equals(bodyMethod)) {
            return jsonReply(400, rpcErrorJson(id, -32020,
                    "HeaderMismatch: MCP-Method '" + hdrMethod + "' disagrees with body method '" + bodyMethod + "'"));
        }
        String hdrName = request.header("MCP-Name");
        if (hdrName != null && !hdrName.isEmpty()) {
            String bodyTarget = extractBodyTarget(env.get("params"));
            if (bodyTarget != null && !hdrName.equals(bodyTarget)) {
                return jsonReply(400, rpcErrorJson(id, -32020,
                        "HeaderMismatch: MCP-Name '" + hdrName + "' disagrees with body target '" + bodyTarget + "'"));
            }
        }
        return null;
    }

    private HttpResponse finalizeOk(String method, String reply) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        if (sessionsEnabled && !McpServer.REVISION_2026_07_28.equals(server.revision())
                && "initialize".equals(method) && !hasErrorField(reply)) {
            String sessionId = UUID.randomUUID().toString();
            activeSessions.add(sessionId);
            headers.put("Mcp-Session-Id", sessionId);
        }
        return new HttpResponse(200, headers, reply);
    }

    private boolean isStatelessRequest(HttpRequest request) {
        String ver = request.header("MCP-Protocol-Version");
        return McpServer.REVISION_2026_07_28.equals(ver)
                || (ver == null && McpServer.REVISION_2026_07_28.equals(server.revision()));
    }

    private boolean requiresExistingSession(String method) {
        return sessionsEnabled
                && !McpServer.REVISION_2026_07_28.equals(server.revision())
                && !"initialize".equals(method)
                && !"server/discover".equals(method);
    }

    private boolean isValidSession(String sessionId) {
        return sessionId != null && activeSessions.contains(sessionId);
    }

    private static String extractBearerToken(String auth) {
        if (auth == null) return null;
        String trimmed = auth.trim();
        if (trimmed.length() <= 7 || !trimmed.substring(0, 7).toLowerCase(Locale.ROOT).equals("bearer ")) {
            return null;
        }
        String token = trimmed.substring(7).trim();
        return token.isEmpty() ? null : token;
    }

    private static String extractBodyTarget(Object rawParams) {
        if (!(rawParams instanceof Map<?, ?> map)) return null;
        if (map.get("name") instanceof String name) return name;
        if (map.get("uri") instanceof String uri) return uri;
        return null;
    }

    private static boolean hasErrorField(String rawReply) {
        Map<String, Object> parsed = Json.parseObject(rawReply);
        return parsed.get("error") != null;
    }

    private static boolean isErrorCode(String rawReply, int expectedCode) {
        Map<String, Object> parsed = Json.parseObject(rawReply);
        if (!(parsed.get("error") instanceof Map<?, ?> err)) return false;
        Object code = err.get("code");
        return code instanceof Number num && num.intValue() == expectedCode;
    }

    private static HttpResponse jsonReply(int status, String body) {
        return new HttpResponse(status, Map.of("Content-Type", "application/json"), body);
    }

    private static String rpcErrorJson(Object id, int code, String message) {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("jsonrpc", "2.0");
        env.put("id", id);
        env.put("error", Map.of("code", Integer.valueOf(code), "message", message));
        return Json.stringify(env);
    }

    private void serveJdkExchange(HttpExchange exchange) throws IOException {
        try (exchange) {
            Map<String, String> reqHeaders = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> e : exchange.getRequestHeaders().entrySet()) {
                if (!e.getValue().isEmpty()) {
                    reqHeaders.put(e.getKey(), e.getValue().get(0));
                }
            }
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String path = exchange.getRequestURI() == null ? "/" : exchange.getRequestURI().getRawPath();
            HttpResponse resp = handle(new HttpRequest(exchange.getRequestMethod(), path, reqHeaders, body));
            for (Map.Entry<String, String> h : resp.headers().entrySet()) {
                exchange.getResponseHeaders().set(h.getKey(), h.getValue());
            }
            byte[] outBytes = resp.body().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(resp.status(), outBytes.length == 0 ? -1 : outBytes.length);
            if (outBytes.length > 0) {
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(outBytes);
                }
            }
        }
    }
}

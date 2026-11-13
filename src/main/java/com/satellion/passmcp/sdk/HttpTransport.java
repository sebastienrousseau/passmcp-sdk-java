// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * Client-side Streamable HTTP transport with a pluggable {@link Exchange} function for offline
 * testing and a standard {@link HttpClient} adapter for production HTTPS connections.
 */
public final class HttpTransport implements Function<String, String> {
    /** Pluggable synchronous HTTP exchange function. */
    @FunctionalInterface
    public interface Exchange {
        /** Executes an HTTP request and returns the HTTP response. */
        HttpProcessor.HttpResponse send(HttpProcessor.HttpRequest request) throws IOException;
    }

    private final String path;
    private final Exchange exchange;
    private String bearerToken;
    private String origin;
    private String sessionId;
    private boolean statelessHeaders = true;

    /** Creates an HTTP transport using {@code exchange} targeting {@code path}. */
    public HttpTransport(String path, Exchange exchange) {
        this.path = (path == null || path.isEmpty()) ? "/mcp" : path;
        this.exchange = Objects.requireNonNull(exchange, "exchange");
    }

    /** Creates an in-memory HTTP transport wired directly to {@code processor}. */
    public static HttpTransport inMemory(HttpProcessor processor) {
        Objects.requireNonNull(processor, "processor");
        return new HttpTransport("/mcp", processor::handle);
    }

    /** Creates a Streamable HTTP transport backed by JDK {@link HttpClient}. */
    public static HttpTransport usingJdkHttpClient(URI endpoint, HttpClient client) {
        Objects.requireNonNull(endpoint, "endpoint");
        Objects.requireNonNull(client, "client");
        String reqPath = (endpoint.getRawPath() == null || endpoint.getRawPath().isEmpty())
                ? "/"
                : endpoint.getRawPath();
        return new HttpTransport(reqPath, req -> sendViaJdkClient(endpoint, client, req));
    }

    /** Sets the optional {@code Authorization: Bearer <token>} credential. */
    public HttpTransport setBearerToken(String token) {
        this.bearerToken = token;
        return this;
    }

    /** Sets an optional {@code Origin} request header. */
    public HttpTransport setOrigin(String originHeader) {
        this.origin = originHeader;
        return this;
    }

    /** Enables or disables {@code 2026-07-28} mirrored headers ({@code MCP-Protocol-Version}, {@code MCP-Method}). */
    public HttpTransport setStatelessHeaders(boolean enabled) {
        this.statelessHeaders = enabled;
        return this;
    }

    /** Overrides or clears the current {@code Mcp-Session-Id} header value. */
    public HttpTransport setSessionId(String value) {
        this.sessionId = value;
        return this;
    }

    /** @return current {@code Mcp-Session-Id} tracked from {@code initialize}, or {@code null} */
    public String sessionId() {
        return sessionId;
    }

    @Override
    public String apply(String rawJson) {
        Objects.requireNonNull(rawJson, "rawJson");
        Map<String, String> headers = buildHeaders(rawJson);
        HttpProcessor.HttpResponse resp;
        try {
            resp = exchange.send(new HttpProcessor.HttpRequest("POST", path, headers, rawJson));
        } catch (IOException ex) {
            throw new UncheckedIOException("Streamable HTTP request failed", ex);
        }
        String issuedSession = resp.header("Mcp-Session-Id");
        if (issuedSession != null && !issuedSession.isEmpty()) {
            this.sessionId = issuedSession;
        }
        return interpretResponse(resp);
    }

    private Map<String, String> buildHeaders(String rawJson) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Accept", "application/json, text/event-stream");
        if (bearerToken != null && !bearerToken.isEmpty()) {
            headers.put("Authorization", "Bearer " + bearerToken);
        }
        if (origin != null && !origin.isEmpty()) {
            headers.put("Origin", origin);
        }
        if (sessionId != null && !sessionId.isEmpty()) {
            headers.put("Mcp-Session-Id", sessionId);
        }
        if (statelessHeaders) {
            populateMirroredHeaders(headers, rawJson);
        }
        return headers;
    }

    private static void populateMirroredHeaders(Map<String, String> headers, String rawJson) {
        headers.put("MCP-Protocol-Version", McpServer.REVISION_2026_07_28);
        try {
            Map<String, Object> env = Json.parseObject(rawJson);
            putIfNonEmpty(headers, "MCP-Method", env.get("method"));
            putIfNonEmpty(headers, "MCP-Name", extractTargetName(env.get("params")));
        } catch (IllegalArgumentException ignored) {
            // Leave mirrored method unset when caller sends raw non-object test frame.
        }
    }

    private static void putIfNonEmpty(Map<String, String> headers, String header, Object candidate) {
        if (candidate instanceof String s && !s.isEmpty()) {
            headers.put(header, s);
        }
    }

    private static Object extractTargetName(Object rawParams) {
        if (!(rawParams instanceof Map<?, ?> params)) {
            return null;
        }
        return params.containsKey("name") ? params.get("name") : params.get("uri");
    }

    private static String interpretResponse(HttpProcessor.HttpResponse resp) {
        int status = resp.status();
        if (status == 202) {
            return "";
        }
        if (status == 401) {
            String www = resp.header("WWW-Authenticate");
            throw new SecurityException("HTTP 401 Unauthorized" + (www == null ? "" : ": " + www));
        }
        if (status == 403) {
            throw new SecurityException("HTTP 403 Forbidden");
        }
        if (!resp.body().isEmpty() && (status == 200 || status == 400 || status == 404)) {
            return resp.body();
        }
        throw new IllegalStateException("Unexpected HTTP status " + status);
    }

    private static HttpProcessor.HttpResponse sendViaJdkClient(
            URI endpoint, HttpClient client, HttpProcessor.HttpRequest req) throws IOException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint)
                .method(req.method(), HttpRequest.BodyPublishers.ofString(req.body()));
        for (Map.Entry<String, String> h : req.headers().entrySet()) {
            builder.header(h.getKey(), h.getValue());
        }
        try {
            HttpResponse<String> jdkResp = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            Map<String, String> respHeaders = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> e : jdkResp.headers().map().entrySet()) {
                if (!e.getValue().isEmpty()) {
                    respHeaders.put(e.getKey(), e.getValue().get(0));
                }
            }
            return new HttpProcessor.HttpResponse(jdkResp.statusCode(), respHeaders, jdkResp.body());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted during HTTP request", ex);
        }
    }
}

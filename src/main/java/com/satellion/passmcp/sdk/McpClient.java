// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

/**
 * Policy-enforcing MCP JSON-RPC 2.0 client with read-only-by-default tool
 * execution, SEP-2549 cache metadata validation, and offline attestation gating.
 */
public final class McpClient {
    /**
     * Exception raised when the remote MCP server returns a JSON-RPC error object.
     */
    public static final class RpcException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final int code;
        private final String dataJson;

        /**
         * Creates an RPC exception from a JSON-RPC error payload.
         *
         * @param code JSON-RPC error code
         * @param message error message
         * @param data optional structured {@code error.data} object
         */
        public RpcException(int code, String message, Map<String, Object> data) {
            super(message);
            this.code = code;
            this.dataJson = (data == null || data.isEmpty()) ? null : Json.stringify(data);
        }

        /** @return JSON-RPC error code */
        public int code() {
            return code;
        }

        /** @return structured {@code error.data} map (empty if absent) */
        public Map<String, Object> data() {
            return dataJson == null ? Map.of() : Map.copyOf(Json.parseObject(dataJson));
        }
    }

    private final Function<String, String> transport;
    private final Policy policy;
    private final AtomicLong nextId = new AtomicLong(1);
    private String negotiatedRevision = McpServer.REVISION_2026_07_28;
    private Map<String, Tool> cachedTools;

    /**
     * Creates a client with the strict default read-only {@link Policy}.
     *
     * @param transport synchronous JSON-RPC transport function (for example {@code server::handleJson})
     */
    public McpClient(Function<String, String> transport) {
        this(transport, Policy.readOnly());
    }

    /**
     * Creates a client with an explicit tool execution {@link Policy}.
     *
     * @param transport synchronous JSON-RPC transport function
     * @param policy execution safety policy
     */
    public McpClient(Function<String, String> transport, Policy policy) {
        this.transport = Objects.requireNonNull(transport, "transport");
        this.policy = Objects.requireNonNull(policy, "policy");
    }

    /**
     * Creates a client connected directly to an in-process {@link McpServer} with read-only policy.
     *
     * @param server target server
     * @return connected {@link McpClient}
     */
    public static McpClient forServer(McpServer server) {
        Objects.requireNonNull(server, "server");
        return new McpClient(server::handleJson, Policy.readOnly());
    }

    /**
     * Enforces offline attestation coverage for {@code (transportKind, endpoint)} before use.
     *
     * @param statement verified evaluation statement
     * @param transportKind expected transport ({@code http} or {@code stdio})
     * @param endpoint expected server endpoint
     * @return this client
     */
    public McpClient requireAttestation(Statement statement, String transportKind, String endpoint) {
        Objects.requireNonNull(statement, "statement");
        AttestationVerifier.validate(statement);
        if (!statement.covers(transportKind, endpoint)) {
            throw new SecurityException("Attestation does not cover " + transportKind + " " + endpoint);
        }
        return this;
    }

    /** @return active tool execution {@link Policy} */
    public Policy policy() {
        return policy;
    }

    /**
     * Performs stateless {@code server/discover} and caches declared tools if present.
     *
     * @return parsed discovery result object
     */
    public Map<String, Object> discover() {
        Map<String, Object> res = rpc("server/discover", Map.of());
        String rev = Json.optString(res, "protocolVersion");
        if (rev != null && !rev.isEmpty()) {
            negotiatedRevision = rev;
        }
        validateStatelessMetaIfRequired(res);
        if (res.get("tools") instanceof List<?>) {
            cacheToolList(Json.asArray(res.get("tools"), "tools"));
        }
        return res;
    }

    /**
     * Performs the MCP {@code initialize} handshake followed by {@code notifications/initialized}.
     *
     * @return initialize result map
     */
    public Map<String, Object> initialize() {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("protocolVersion", McpServer.REVISION_2026_07_28);
        params.put("capabilities", Map.of());
        params.put("clientInfo", Map.of("name", "passmcp-sdk-java", "version", "0.0.10"));
        Map<String, Object> res = rpc("initialize", params);
        String rev = Json.optString(res, "protocolVersion");
        if (rev != null && !rev.isEmpty()) {
            negotiatedRevision = rev;
        }
        notify("notifications/initialized");
        return res;
    }

    /**
     * Sends {@code ping} and verifies an object response.
     */
    public void ping() {
        rpc("ping", Map.of());
    }

    /**
     * Lists tools from {@code tools/list}, validating SEP-2549 {@code _meta} on {@code 2026-07-28}.
     *
     * @return advertised tools
     */
    public List<Tool> listTools() {
        Map<String, Object> res = rpc("tools/list", Map.of());
        validateStatelessMetaIfRequired(res);
        List<Object> rawTools = Json.asArray(res.get("tools"), "tools");
        return cacheToolList(rawTools);
    }

    /**
     * Enforces {@link Policy} against the advertised tool annotations, then invokes {@code tools/call}.
     *
     * @param name tool name
     * @param arguments tool arguments map
     * @return first text content item returned by the tool
     */
    public String callTool(String name, Map<String, Object> arguments) {
        if (cachedTools == null) {
            listTools();
        }
        Tool tool = cachedTools.get(name);
        policy.enforce(tool);
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("name", name);
        params.put("arguments", arguments == null ? Map.of() : arguments);
        Map<String, Object> res = rpc("tools/call", params);
        List<Object> content = Json.asArray(res.get("content"), "content");
        if (content.isEmpty()) {
            return "";
        }
        Map<String, Object> first = Json.asObject(content.get(0), "content[0]");
        String text = Json.optString(first, "text");
        return text == null ? "" : text;
    }

    /**
     * Reads a resource URI via {@code resources/read}.
     *
     * @param uri resource URI
     * @return resource text content
     */
    public String readResource(String uri) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("uri", uri);
        Map<String, Object> res = rpc("resources/read", params);
        List<Object> contents = Json.asArray(res.get("contents"), "contents");
        if (contents.isEmpty()) {
            return "";
        }
        Map<String, Object> first = Json.asObject(contents.get(0), "contents[0]");
        String text = Json.optString(first, "text");
        return text == null ? "" : text;
    }

    /**
     * Invokes an arbitrary JSON-RPC method and returns the {@code result} object.
     *
     * @param method JSON-RPC method name
     * @param params method parameters object
     * @return result map
     */
    public Map<String, Object> rpc(String method, Map<String, Object> params) {
        long id = nextId.getAndIncrement();
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("jsonrpc", "2.0");
        req.put("id", Long.valueOf(id));
        req.put("method", method);
        req.put("params", params == null ? Map.of() : params);
        String rawResp = transport.apply(Json.stringify(req));
        Map<String, Object> resp = Json.parseObject(rawResp);
        if (resp.containsKey("error") && resp.get("error") != null) {
            Map<String, Object> err = Json.asObject(resp.get("error"), "error");
            int code = Json.reqInt(err, "code");
            String msg = Json.optString(err, "message");
            Map<String, Object> data = err.get("data") instanceof Map<?, ?>
                    ? Json.asObject(err.get("data"), "error.data")
                    : Map.of();
            throw new RpcException(code, msg == null ? "RPC error" : msg, data);
        }
        return Json.asObject(resp.get("result"), "result");
    }

    private void notify(String method) {
        Map<String, Object> note = new LinkedHashMap<>();
        note.put("jsonrpc", "2.0");
        note.put("method", method);
        transport.apply(Json.stringify(note));
    }

    private void validateStatelessMetaIfRequired(Map<String, Object> res) {
        if (McpServer.REVISION_2026_07_28.equals(negotiatedRevision)) {
            CacheHints.fromResult(res);
        }
    }

    private List<Tool> cacheToolList(List<Object> rawTools) {
        Map<String, Tool> byName = new LinkedHashMap<>(rawTools.size());
        List<Tool> out = new ArrayList<>(rawTools.size());
        for (Object item : rawTools) {
            Tool tool = Tool.fromWireMap(Json.asObject(item, "tool"));
            byName.put(tool.name(), tool);
            out.add(tool);
        }
        this.cachedTools = byName;
        return out;
    }
}

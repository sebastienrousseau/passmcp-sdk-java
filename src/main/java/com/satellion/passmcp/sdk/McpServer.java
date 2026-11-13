// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Capability-gated MCP JSON-RPC 2.0 server supporting revisions
 * {@code 2026-07-28} (default), {@code 2025-11-25}, and {@code 2025-06-18}.
 */
public final class McpServer {
    /** Default stateless MCP specification revision. */
    public static final String REVISION_2026_07_28 = "2026-07-28";
    /** Handshake MCP specification revision 2025-11-25. */
    public static final String REVISION_2025_11_25 = "2025-11-25";
    /** Handshake MCP specification revision 2025-06-18. */
    public static final String REVISION_2025_06_18 = "2025-06-18";

    private static final List<String> SUPPORTED_REVISIONS = List.of(
            REVISION_2026_07_28, REVISION_2025_11_25, REVISION_2025_06_18);
    private static final Set<String> REVISION_SET = Set.copyOf(SUPPORTED_REVISIONS);

    /** Functional reader for a registered resource URI. */
    @FunctionalInterface
    public interface ResourceReader {
        /** Returns the textual body for {@code uri}. */
        String read(String uri) throws Exception;
    }

    /** Functional renderer for a registered prompt template. */
    @FunctionalInterface
    public interface PromptRenderer {
        /** Renders the prompt message text for {@code arguments}. */
        String render(Map<String, Object> arguments) throws Exception;
    }

    /** Metadata for a single prompt argument. */
    public record PromptArgument(String name, String description, boolean required) {
        /** Validates prompt argument name. */
        public PromptArgument {
            if (name == null || name.trim().isEmpty()) {
                throw new IllegalArgumentException("PromptArgument name must not be empty");
            }
            description = description == null ? "" : description;
        }

        Map<String, Object> toWireMap() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("name", name);
            if (!description.isEmpty()) {
                out.put("description", description);
            }
            out.put("required", Boolean.valueOf(required));
            return out;
        }
    }

    /** HTTP transport status and body envelope produced by {@link #handleHttp(String, String)}. */
    public record HttpReply(int status, String body) {
    }

    private static final class RpcFault extends Exception {
        private static final long serialVersionUID = 1L;
        final int code;
        final String dataJson;

        RpcFault(int code, String message, Map<String, Object> data) {
            super(message);
            this.code = code;
            this.dataJson = data == null ? null : Json.stringify(data);
        }
    }

    private final String name;
    private final String version;
    private final String revision;
    private String instructions = "";
    private CacheHints cacheHints = CacheHints.privateScope(60_000L);
    private OriginGuard originGuard = new OriginGuard(List.of());
    private final Map<String, CatalogEntries.RegisteredTool> tools = new LinkedHashMap<>();
    private final Map<String, CatalogEntries.RegisteredResource> resources = new LinkedHashMap<>();
    private final List<CatalogEntries.ResourceTemplate> templates = new ArrayList<>();
    private final Map<String, CatalogEntries.RegisteredPrompt> prompts = new LinkedHashMap<>();

    /** Creates an MCP server targeting the default {@code 2026-07-28} revision. */
    public McpServer(String name, String version) {
        this(name, version, REVISION_2026_07_28);
    }

    /** Creates an MCP server targeting a specific supported MCP revision. */
    public McpServer(String name, String version, String revision) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Server name must not be empty");
        }
        if (version == null || version.trim().isEmpty()) {
            throw new IllegalArgumentException("Server version must not be empty");
        }
        if (!REVISION_SET.contains(revision)) {
            throw new IllegalArgumentException("Unsupported MCP revision: " + revision);
        }
        this.name = name;
        this.version = version;
        this.revision = revision;
    }

    /** @return server name */
    public String name() { return name; }

    /** @return server version */
    public String version() { return version; }

    /** @return configured MCP specification revision */
    public String revision() { return revision; }

    /** @return configured HTTP {@link OriginGuard} */
    public OriginGuard originGuard() { return originGuard; }

    /** Sets optional human/model instructions returned in {@code initialize} and {@code server/discover}. */
    public McpServer setInstructions(String value) {
        this.instructions = value == null ? "" : value;
        return this;
    }

    /** Configures SEP-2549 cache hints emitted on {@code 2026-07-28} list responses. */
    public McpServer setCacheHints(CacheHints cacheHints) {
        this.cacheHints = Objects.requireNonNull(cacheHints, "cacheHints");
        return this;
    }

    /** Configures the HTTP {@code Origin} allowlist guard. */
    public McpServer setOriginGuard(OriginGuard originGuard) {
        this.originGuard = Objects.requireNonNull(originGuard, "originGuard");
        return this;
    }

    /** Registers a text tool and its handler, enabling the {@code tools} capability. */
    public McpServer registerTool(Tool tool, Tool.Handler handler) {
        Objects.requireNonNull(handler, "handler");
        return registerStructuredTool(tool, args -> new Tool.Result(handler.invoke(args), null));
    }

    /** Registers a structured tool returning both text content and {@code structuredContent}. */
    public McpServer registerStructuredTool(Tool tool, Tool.StructuredHandler handler) {
        Objects.requireNonNull(tool, "tool");
        Objects.requireNonNull(handler, "handler");
        tools.put(tool.name(), new CatalogEntries.RegisteredTool(tool, handler));
        return this;
    }

    /** Registers a resource URI and reader, enabling the {@code resources} capability. */
    public McpServer registerResource(String uri, String resourceName, String mimeType, ResourceReader reader) {
        return registerResource(uri, resourceName, null, null, mimeType, reader);
    }

    /** Registers a resource URI with title and description metadata. */
    public McpServer registerResource(
            String uri, String resourceName, String title, String description, String mimeType, ResourceReader reader) {
        if (uri == null || uri.trim().isEmpty()) {
            throw new IllegalArgumentException("Resource URI must not be empty");
        }
        resources.put(uri, new CatalogEntries.RegisteredResource(
                uri,
                Objects.requireNonNull(resourceName, "resourceName"),
                title,
                description,
                Objects.requireNonNull(mimeType, "mimeType"),
                Objects.requireNonNull(reader, "reader")));
        return this;
    }

    /** Registers a resource template, enabling the {@code resources} capability. */
    public McpServer registerResourceTemplate(String uriTemplate, String templateName, String mimeType) {
        if (uriTemplate == null || uriTemplate.trim().isEmpty()) {
            throw new IllegalArgumentException("URI template must not be empty");
        }
        templates.add(new CatalogEntries.ResourceTemplate(
                uriTemplate,
                Objects.requireNonNull(templateName, "templateName"),
                Objects.requireNonNull(mimeType, "mimeType")));
        return this;
    }

    /** Registers a prompt template without declared arguments. */
    public McpServer registerPrompt(String promptName, String description, PromptRenderer renderer) {
        return registerPrompt(promptName, null, description, List.of(), renderer);
    }

    /** Registers a prompt template with title and typed argument definitions. */
    public McpServer registerPrompt(
            String promptName,
            String title,
            String description,
            List<PromptArgument> arguments,
            PromptRenderer renderer) {
        if (promptName == null || promptName.trim().isEmpty()) {
            throw new IllegalArgumentException("Prompt name must not be empty");
        }
        prompts.put(promptName, new CatalogEntries.RegisteredPrompt(
                promptName,
                title,
                Objects.requireNonNull(description, "description"),
                arguments == null ? List.of() : List.copyOf(arguments),
                Objects.requireNonNull(renderer, "renderer")));
        return this;
    }

    /** Evaluates HTTP {@code Origin} policy before dispatching a JSON-RPC payload. */
    public HttpReply handleHttp(String originHeader, String rawJson) {
        if (!originGuard.isAllowed(originHeader)) {
            return new HttpReply(403, "");
        }
        String response = handleJson(rawJson);
        return response.isEmpty() ? new HttpReply(202, "") : new HttpReply(200, response);
    }

    /** Dispatches a single JSON-RPC 2.0 request or notification string. */
    public String handleJson(String raw) {
        Object parsed;
        try {
            parsed = Json.parse(raw);
        } catch (IllegalArgumentException ex) {
            return errorResponse(null, -32700, "Parse error: invalid JSON payload", null);
        }
        if (!(parsed instanceof Map<?, ?>)) {
            return errorResponse(null, -32600, "Invalid Request: expected JSON object", null);
        }
        return handleEnvelope(Json.asObject(parsed, "request"));
    }

    private String handleEnvelope(Map<String, Object> req) {
        Object id = sanitizeId(req.get("id"));
        String method = validRpcMethod(req);
        if (method == null) {
            return errorResponse(id, -32600, "Invalid Request: jsonrpc must be '2.0' with non-empty method", null);
        }
        if (!req.containsKey("id")) {
            return "";
        }
        Map<String, Object> params = extractParams(req.get("params"));
        if (params == null) {
            return errorResponse(id, -32602, "Invalid params: expected JSON object", null);
        }
        try {
            return resultResponse(id, dispatchMethod(method, params));
        } catch (RpcFault fault) {
            Map<String, Object> data = fault.dataJson == null ? null : Json.parseObject(fault.dataJson);
            return errorResponse(id, fault.code, fault.getMessage(), data);
        }
    }

    private static String validRpcMethod(Map<String, Object> req) {
        if (!"2.0".equals(req.get("jsonrpc"))) return null;
        return (req.get("method") instanceof String m && !m.isEmpty()) ? m : null;
    }

    private Object dispatchMethod(String method, Map<String, Object> params) throws RpcFault {
        return switch (method) {
            case "initialize" -> handleInitialize();
            case "ping" -> Map.of();
            case "server/discover" -> handleDiscover();
            case "tools/call" -> handleToolsCall(params);
            case "resources/read" -> handleResourcesRead(params);
            case "prompts/get" -> handlePromptsGet(params);
            default -> dispatchListMethod(method);
        };
    }

    private Object dispatchListMethod(String method) throws RpcFault {
        return switch (method) {
            case "tools/list" -> listPayload(!tools.isEmpty(), "tools", "tools", wireTools());
            case "resources/list" -> listPayload(hasResources(), "resources", "resources", wireResources());
            case "resources/templates/list" -> listPayload(hasResources(), "resources", "resourceTemplates", wireTemplates());
            case "prompts/list" -> listPayload(!prompts.isEmpty(), "prompts", "prompts", wirePrompts());
            default -> throw new RpcFault(-32601, "Method not found: unknown method '" + method + "'", null);
        };
    }

    private Map<String, Object> handleInitialize() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("protocolVersion", revision);
        out.put("capabilities", derivedCapabilities());
        out.put("serverInfo", serverInfoMap());
        if (!instructions.isEmpty()) {
            out.put("instructions", instructions);
        }
        return out;
    }

    private Map<String, Object> handleDiscover() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("resultType", "discover");
        out.put("protocolVersion", revision);
        out.put("supportedVersions", SUPPORTED_REVISIONS);
        out.put("serverInfo", serverInfoMap());
        out.put("capabilities", derivedCapabilities());
        if (!instructions.isEmpty()) {
            out.put("instructions", instructions);
        }
        if (!tools.isEmpty()) out.put("tools", wireTools());
        if (hasResources()) {
            out.put("resources", wireResources());
            out.put("resourceTemplates", wireTemplates());
        }
        if (!prompts.isEmpty()) out.put("prompts", wirePrompts());
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("io.modelcontextprotocol/serverInfo", serverInfoMap());
        if (REVISION_2026_07_28.equals(revision)) {
            meta.putAll(cacheHints.toMetaMap());
            out.put("ttlMs", Long.valueOf(cacheHints.ttlMs()));
            out.put("cacheScope", cacheHints.cacheScope());
        }
        out.put("_meta", meta);
        return out;
    }

    private Map<String, Object> listPayload(
            boolean enabled, String capName, String field, List<Map<String, Object>> items) throws RpcFault {
        requireCapability(enabled, capName);
        Map<String, Object> out = new LinkedHashMap<>();
        if (REVISION_2026_07_28.equals(revision)) {
            out.put("resultType", "complete");
        }
        out.put(field, items);
        if (REVISION_2026_07_28.equals(revision)) {
            cacheHints.applyToListResult(out);
        }
        return out;
    }

    private Map<String, Object> handleToolsCall(Map<String, Object> params) throws RpcFault {
        requireCapability(!tools.isEmpty(), "tools");
        String toolName = requiredParamString(params, "name");
        CatalogEntries.RegisteredTool reg = tools.get(toolName);
        if (reg == null) {
            throw new RpcFault(-32602, "Unknown tool '" + toolName + "'; call tools/list for available tools", null);
        }
        Map<String, Object> args = extractObjectOrEmpty(params.get("arguments"));
        String schemaErr = SchemaValidator.validateToolArguments(reg.tool().inputSchema(), args);
        if (schemaErr != null) {
            throw new RpcFault(-32602, schemaErr, null);
        }
        try {
            Tool.Result output = reg.handler().invoke(args);
            return toolContentResult(output.text(), output.structuredContent(), false);
        } catch (Exception ex) {
            String msg = ex.getMessage() == null ? "Tool execution failed; check input parameters" : ex.getMessage();
            return toolContentResult(msg, null, true);
        }
    }

    private Map<String, Object> handleResourcesRead(Map<String, Object> params) throws RpcFault {
        requireCapability(hasResources(), "resources");
        String uri = requiredParamString(params, "uri");
        CatalogEntries.RegisteredResource reg = resources.get(uri);
        if (reg == null) {
            int code = REVISION_2026_07_28.equals(revision) ? -32602 : -32002;
            throw new RpcFault(code, "Resource not found; call resources/list for available URIs", Map.of("uri", uri));
        }
        try {
            String body = reg.reader().read(uri);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("uri", reg.uri());
            item.put("mimeType", reg.mimeType());
            item.put("text", body == null ? "" : body);
            return Map.of("contents", List.of(item));
        } catch (Exception ex) {
            throw new RpcFault(-32603, "Failed to read resource", null);
        }
    }

    private Map<String, Object> handlePromptsGet(Map<String, Object> params) throws RpcFault {
        requireCapability(!prompts.isEmpty(), "prompts");
        String promptName = requiredParamString(params, "name");
        CatalogEntries.RegisteredPrompt reg = prompts.get(promptName);
        if (reg == null) {
            throw new RpcFault(-32602, "Unknown prompt '" + promptName + "'; call prompts/list first", null);
        }
        Map<String, Object> args = extractObjectOrEmpty(params.get("arguments"));
        String argErr = SchemaValidator.validatePromptArguments(reg.arguments(), args);
        if (argErr != null) {
            throw new RpcFault(-32602, argErr, null);
        }
        try {
            String text = reg.renderer().render(args);
            Map<String, Object> msg = new LinkedHashMap<>();
            msg.put("role", "user");
            msg.put("content", Map.of("type", "text", "text", text == null ? "" : text));
            return Map.of("description", reg.description(), "messages", List.of(msg));
        } catch (Exception ex) {
            throw new RpcFault(-32603, "Failed to render prompt", null);
        }
    }

    private Map<String, Object> derivedCapabilities() {
        Map<String, Object> caps = new LinkedHashMap<>();
        if (!tools.isEmpty()) caps.put("tools", Map.of());
        if (hasResources()) caps.put("resources", Map.of());
        if (!prompts.isEmpty()) caps.put("prompts", Map.of());
        return caps;
    }

    private Map<String, Object> serverInfoMap() {
        return Map.of("name", name, "version", version);
    }

    private List<Map<String, Object>> wireTools() {
        List<Map<String, Object>> list = new ArrayList<>(tools.size());
        for (CatalogEntries.RegisteredTool rt : tools.values()) list.add(rt.tool().toWireMap());
        return list;
    }

    private List<Map<String, Object>> wireResources() {
        List<Map<String, Object>> list = new ArrayList<>(resources.size());
        for (CatalogEntries.RegisteredResource rr : resources.values()) list.add(rr.toWireMap());
        return list;
    }

    private List<Map<String, Object>> wireTemplates() {
        List<Map<String, Object>> list = new ArrayList<>(templates.size());
        for (CatalogEntries.ResourceTemplate tpl : templates) list.add(tpl.toWireMap());
        return list;
    }

    private List<Map<String, Object>> wirePrompts() {
        List<Map<String, Object>> list = new ArrayList<>(prompts.size());
        for (CatalogEntries.RegisteredPrompt rp : prompts.values()) list.add(rp.toWireMap());
        return list;
    }

    private boolean hasResources() { return !resources.isEmpty() || !templates.isEmpty(); }

    private static void requireCapability(boolean enabled, String capability) throws RpcFault {
        if (!enabled) throw new RpcFault(-32601, "Capability not declared: " + capability, null);
    }

    private static String requiredParamString(Map<String, Object> params, String key) throws RpcFault {
        Object val = params.get(key);
        if (!(val instanceof String s) || s.trim().isEmpty()) {
            throw new RpcFault(-32602, "Invalid params: missing required string '" + key + "'", null);
        }
        return s;
    }

    private static Map<String, Object> extractParams(Object raw) {
        if (raw == null) return Map.of();
        return raw instanceof Map<?, ?> ? Json.asObject(raw, "params") : null;
    }

    private static Map<String, Object> extractObjectOrEmpty(Object raw) throws RpcFault {
        if (raw == null) return Map.of();
        if (!(raw instanceof Map<?, ?>)) {
            throw new RpcFault(-32602, "Invalid params: arguments must be a JSON object", null);
        }
        return Json.asObject(raw, "arguments");
    }

    private static Map<String, Object> toolContentResult(
            String text, Map<String, Object> structured, boolean isError) {
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("content", List.of(Map.of("type", "text", "text", text)));
        if (structured != null) res.put("structuredContent", structured);
        res.put("isError", Boolean.valueOf(isError));
        return res;
    }

    private static Object sanitizeId(Object rawId) {
        return (rawId instanceof String || rawId instanceof Number) ? rawId : null;
    }

    private static String resultResponse(Object id, Object result) {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("jsonrpc", "2.0");
        env.put("id", id);
        env.put("result", result);
        return Json.stringify(env);
    }

    private static String errorResponse(Object id, int code, String message, Map<String, Object> data) {
        Map<String, Object> err = new LinkedHashMap<>();
        err.put("code", Integer.valueOf(code));
        err.put("message", message);
        if (data != null) err.put("data", data);
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("jsonrpc", "2.0");
        env.put("id", id);
        env.put("error", err);
        return Json.stringify(env);
    }
}

// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Descriptor and invocation contracts for an MCP tool, carrying schemas, titles,
 * and explicit safety annotations used by {@link Policy}.
 */
public final class Tool {
    /** Text-only tool handler invoked by {@link McpServer} for {@code tools/call}. */
    @FunctionalInterface
    public interface Handler {
        /** Executes the tool and returns text output. */
        String invoke(Map<String, Object> arguments) throws Exception;
    }

    /** Structured tool result carrying both text content and optional {@code structuredContent}. */
    public record Result(String text, Map<String, Object> structuredContent) {
        /** Defensive copy of structuredContent. */
        public Result {
            text = text == null ? "" : text;
            structuredContent = structuredContent == null ? null : Map.copyOf(structuredContent);
        }
    }

    /** Structured tool handler returning both text and structured JSON output. */
    @FunctionalInterface
    public interface StructuredHandler {
        /** Executes the tool and returns a {@link Result}. */
        Result invoke(Map<String, Object> arguments) throws Exception;
    }

    /** Fluent builder for full MCP tool descriptors. */
    public static final class Builder {
        private final String name;
        private final String description;
        private String title;
        private Map<String, Object> inputSchema = defaultSchema();
        private Map<String, Object> outputSchema;
        private boolean annotated = true;
        private boolean readOnlyHint = true;
        private boolean destructiveHint;
        private boolean idempotentHint = true;
        private boolean openWorldHint;

        private Builder(String name, String description) {
            this.name = name;
            this.description = description;
        }

        /** Sets the human-readable title emitted on the tool and its annotations. */
        public Builder title(String value) {
            this.title = value;
            return this;
        }

        /** Sets the input JSON Schema object. */
        public Builder inputSchema(Map<String, Object> schema) {
            this.inputSchema = Objects.requireNonNull(schema, "schema");
            return this;
        }

        /** Sets the output JSON Schema object. */
        public Builder outputSchema(Map<String, Object> schema) {
            this.outputSchema = schema;
            return this;
        }

        /** Configures explicit MCP tool behaviour annotations. */
        public Builder annotations(boolean readOnly, boolean destructive, boolean idempotent, boolean openWorld) {
            this.annotated = true;
            this.readOnlyHint = readOnly;
            this.destructiveHint = destructive;
            this.idempotentHint = idempotent;
            this.openWorldHint = openWorld;
            return this;
        }

        /** Builds the immutable {@link Tool}. */
        public Tool build() {
            return new Tool(
                    name, title, description, inputSchema, outputSchema,
                    annotated, readOnlyHint, destructiveHint, idempotentHint, openWorldHint);
        }
    }

    private final String name;
    private final String title;
    private final String description;
    private final Map<String, Object> inputSchema;
    private final Map<String, Object> outputSchema;
    private final boolean annotated;
    private final boolean readOnlyHint;
    private final boolean destructiveHint;
    private final boolean idempotentHint;
    private final boolean openWorldHint;

    /** Constructs a tool descriptor without title or outputSchema. */
    public Tool(
            String name,
            String description,
            Map<String, Object> inputSchema,
            boolean annotated,
            boolean readOnlyHint,
            boolean destructiveHint,
            boolean idempotentHint,
            boolean openWorldHint) {
        this(name, null, description, inputSchema, null,
                annotated, readOnlyHint, destructiveHint, idempotentHint, openWorldHint);
    }

    /** Constructs a full tool descriptor. */
    public Tool(
            String name,
            String title,
            String description,
            Map<String, Object> inputSchema,
            Map<String, Object> outputSchema,
            boolean annotated,
            boolean readOnlyHint,
            boolean destructiveHint,
            boolean idempotentHint,
            boolean openWorldHint) {
        requireNonBlankName(name);
        Objects.requireNonNull(description, "description");
        this.name = name;
        this.title = normalizeOptionalTitle(title);
        this.description = description;
        this.inputSchema = copyOrDefaultSchema(inputSchema);
        this.outputSchema = outputSchema == null ? null : Map.copyOf(outputSchema);
        this.annotated = annotated;
        this.readOnlyHint = annotated && readOnlyHint;
        this.destructiveHint = !annotated || destructiveHint;
        this.idempotentHint = annotated && idempotentHint;
        this.openWorldHint = annotated && openWorldHint;
    }

    /** Starts a fluent {@link Builder} defaulting to read-only, idempotent, closed-world. */
    public static Builder builder(String name, String description) {
        return new Builder(name, description);
    }

    /** Creates a read-only, idempotent, closed-world tool descriptor with an empty object schema. */
    public static Tool readOnly(String name, String description) {
        return new Tool(name, description, defaultSchema(), true, true, false, true, false);
    }

    /** Creates a read-only tool descriptor with a custom input JSON Schema. */
    public static Tool readOnly(String name, String description, Map<String, Object> inputSchema) {
        return new Tool(name, description, inputSchema, true, true, false, true, false);
    }

    /** Creates a mutating tool descriptor. */
    public static Tool mutating(String name, String description, boolean destructive) {
        return new Tool(name, description, defaultSchema(), true, false, destructive, false, false);
    }

    /** Creates an unannotated tool descriptor (treated as non-read-only per MCP defaults). */
    public static Tool unannotated(String name, String description) {
        return new Tool(name, description, defaultSchema(), false, false, true, false, false);
    }

    /** Parses a wire tool object from {@code tools/list} or {@code server/discover}. */
    public static Tool fromWireMap(Map<String, Object> obj) {
        String name = Json.reqString(obj, "name");
        String title = Json.optString(obj, "title");
        String desc = Objects.requireNonNullElse(Json.optString(obj, "description"), "");
        Map<String, Object> inSchema = optObjectField(obj, "inputSchema", defaultSchema());
        Map<String, Object> outSchema = optObjectField(obj, "outputSchema", null);
        if (!(obj.get("annotations") instanceof Map<?, ?> rawAnn)) {
            return new Tool(name, title, desc, inSchema, outSchema, false, false, true, false, false);
        }
        Map<String, Object> ann = Json.asObject(rawAnn, "annotations");
        return new Tool(
                name, title, desc, inSchema, outSchema,
                true,
                Boolean.TRUE.equals(ann.get("readOnlyHint")),
                !Boolean.FALSE.equals(ann.get("destructiveHint")),
                Boolean.TRUE.equals(ann.get("idempotentHint")),
                Boolean.TRUE.equals(ann.get("openWorldHint")));
    }

    private static void requireNonBlankName(String name) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Tool name must not be blank");
        }
    }

    private static String normalizeOptionalTitle(String title) {
        return (title == null || title.isEmpty()) ? null : title;
    }

    private static Map<String, Object> copyOrDefaultSchema(Map<String, Object> schema) {
        return schema == null ? defaultSchema() : Map.copyOf(schema);
    }

    private static Map<String, Object> optObjectField(
            Map<String, Object> obj, String key, Map<String, Object> fallback) {
        return obj.get(key) instanceof Map<?, ?> m ? Json.asObject(m, key) : fallback;
    }

    /** @return tool name */
    public String name() { return name; }

    /** @return optional tool title */
    public String title() { return title; }

    /** @return tool description */
    public String description() { return description; }

    /** @return JSON Schema map for arguments */
    public Map<String, Object> inputSchema() { return inputSchema; }

    /** @return optional output JSON Schema map */
    public Map<String, Object> outputSchema() { return outputSchema; }

    /** @return {@code true} only when explicitly annotated with {@code readOnlyHint: true} */
    public boolean readOnlyHint() { return readOnlyHint; }

    /** @return {@code true} when destructive or unannotated */
    public boolean destructiveHint() { return destructiveHint; }

    /** Converts this tool descriptor into its MCP JSON-RPC wire map. */
    public Map<String, Object> toWireMap() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("name", name);
        if (title != null) {
            out.put("title", title);
        }
        out.put("description", description);
        out.put("inputSchema", inputSchema);
        if (outputSchema != null) {
            out.put("outputSchema", outputSchema);
        }
        if (annotated) {
            Map<String, Object> ann = new LinkedHashMap<>();
            if (title != null) {
                ann.put("title", title);
            }
            ann.put("readOnlyHint", Boolean.valueOf(readOnlyHint));
            ann.put("destructiveHint", Boolean.valueOf(destructiveHint));
            ann.put("idempotentHint", Boolean.valueOf(idempotentHint));
            ann.put("openWorldHint", Boolean.valueOf(openWorldHint));
            out.put("annotations", ann);
        }
        return out;
    }

    private static Map<String, Object> defaultSchema() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", Map.of());
        schema.put("additionalProperties", Boolean.FALSE);
        return Map.copyOf(schema);
    }
}

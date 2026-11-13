// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.util.List;
import java.util.Map;

/**
 * Package-private JSON Schema and prompt argument validator producing actionable
 * {@code -32602 Invalid params} error messages for MCP callers.
 */
final class SchemaValidator {
    private SchemaValidator() {
    }

    static String validateToolArguments(Map<String, Object> schema, Map<String, Object> args) {
        if (schema == null || schema.isEmpty()) {
            return null;
        }
        String reqErr = checkRequiredFields(schema.get("required"), args);
        if (reqErr != null) {
            return reqErr;
        }
        Map<String, Object> props = schema.get("properties") instanceof Map<?, ?> rawProps
                ? Json.asObject(rawProps, "properties")
                : Map.of();
        if (Boolean.FALSE.equals(schema.get("additionalProperties"))) {
            for (String key : args.keySet()) {
                if (!props.containsKey(key)) {
                    return "Unknown argument '" + key + "'; allowed properties: " + props.keySet();
                }
            }
        }
        return checkPropertyTypes(props, args);
    }

    static String validatePromptArguments(List<McpServer.PromptArgument> declared, Map<String, Object> args) {
        for (McpServer.PromptArgument arg : declared) {
            Object val = args.get(arg.name());
            if (arg.required() && (!(val instanceof String s) || s.trim().isEmpty())) {
                return "Missing required prompt argument '" + arg.name() + "'; provide a non-empty string";
            }
            if (val != null && !(val instanceof String)) {
                return "Prompt argument '" + arg.name() + "' must be a string";
            }
        }
        return null;
    }

    private static String checkRequiredFields(Object rawReq, Map<String, Object> args) {
        if (!(rawReq instanceof List<?> reqList)) {
            return null;
        }
        for (Object item : reqList) {
            if (item instanceof String field && (!args.containsKey(field) || args.get(field) == null)) {
                return "Missing required argument '" + field + "'; provide a valid value";
            }
        }
        return null;
    }

    private static String checkPropertyTypes(Map<String, Object> props, Map<String, Object> args) {
        for (Map.Entry<String, Object> entry : args.entrySet()) {
            Object rawSpec = props.get(entry.getKey());
            if (!(rawSpec instanceof Map<?, ?> specMap) || entry.getValue() == null) {
                continue;
            }
            Object expected = specMap.get("type");
            if (expected instanceof String typeName && !matchesJsonType(typeName, entry.getValue())) {
                return "Argument '" + entry.getKey() + "' must be of type " + typeName;
            }
        }
        return null;
    }

    private static boolean matchesJsonType(String typeName, Object val) {
        return switch (typeName) {
            case "string" -> val instanceof String;
            case "boolean" -> val instanceof Boolean;
            case "integer" -> isWholeNumber(val);
            case "number" -> val instanceof Number;
            case "object" -> val instanceof Map<?, ?>;
            case "array" -> val instanceof List<?>;
            default -> true;
        };
    }

    private static boolean isWholeNumber(Object val) {
        return val instanceof Long || val instanceof Integer;
    }
}

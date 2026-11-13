// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Package-private catalog registry records and JSON-RPC wire serializers for {@link McpServer}.
 */
final class CatalogEntries {
    private CatalogEntries() {
    }

    record RegisteredTool(Tool tool, Tool.StructuredHandler handler) {
    }

    record RegisteredResource(
            String uri,
            String name,
            String title,
            String description,
            String mimeType,
            McpServer.ResourceReader reader) {
        Map<String, Object> toWireMap() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("uri", uri);
            out.put("name", name);
            if (title != null && !title.isEmpty()) {
                out.put("title", title);
            }
            if (description != null && !description.isEmpty()) {
                out.put("description", description);
            }
            out.put("mimeType", mimeType);
            return out;
        }
    }

    record ResourceTemplate(String uriTemplate, String name, String mimeType) {
        Map<String, Object> toWireMap() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("uriTemplate", uriTemplate);
            out.put("name", name);
            out.put("mimeType", mimeType);
            return out;
        }
    }

    record RegisteredPrompt(
            String name,
            String title,
            String description,
            List<McpServer.PromptArgument> arguments,
            McpServer.PromptRenderer renderer) {
        Map<String, Object> toWireMap() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("name", name);
            if (title != null && !title.isEmpty()) {
                out.put("title", title);
            }
            out.put("description", description);
            if (!arguments.isEmpty()) {
                List<Map<String, Object>> wireArgs = new ArrayList<>(arguments.size());
                for (McpServer.PromptArgument arg : arguments) {
                    wireArgs.add(arg.toWireMap());
                }
                out.put("arguments", wireArgs);
            }
            return out;
        }
    }
}

// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import com.satellion.passmcp.sdk.CacheHints;
import com.satellion.passmcp.sdk.Json;
import com.satellion.passmcp.sdk.McpServer;
import com.satellion.passmcp.sdk.StdioServer;
import com.satellion.passmcp.sdk.Tool;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Runnable MCP {@code stdio} reference server demonstrating read-only tools with structured
 * output, SEP-2164 resources, typed prompts, and SEP-2549 list cache hints.
 */
public final class StdioServerExample {
    private StdioServerExample() {
    }

    /** Builds the configured reference {@link McpServer}. */
    public static McpServer buildServer() {
        McpServer srv = new McpServer("passmcp-sdk-java-demo", "0.0.9")
                .setInstructions("Reference MCP server built with passmcp-sdk demonstrating read-only tools, "
                        + "SEP-2164 resources, prompts, and SEP-2549 cache hints.")
                .setCacheHints(CacheHints.ofSeconds(true, 300L, "public"));

        Map<String, Object> inputSchema = new LinkedHashMap<>();
        inputSchema.put("type", "object");
        inputSchema.put("additionalProperties", Boolean.FALSE);
        inputSchema.put("required", List.of("endpoint"));
        inputSchema.put("properties", Map.of(
                "endpoint", Map.of(
                        "type", "string",
                        "description", "HTTPS or stdio target endpoint identifier to inspect")));

        Map<String, Object> outputSchema = new LinkedHashMap<>();
        outputSchema.put("type", "object");
        outputSchema.put("required", List.of("endpoint", "transport"));
        outputSchema.put("properties", Map.of(
                "endpoint", Map.of("type", "string"),
                "transport", Map.of("type", "string")));

        Tool inspectTool = Tool.builder(
                        "inspect_target",
                        "Inspect an MCP server endpoint and classify its transport binding without mutating state.")
                .title("Inspect MCP Target")
                .inputSchema(inputSchema)
                .outputSchema(outputSchema)
                .annotations(true, false, true, false)
                .build();

        srv.registerStructuredTool(inspectTool, args -> {
            String ep = ((String) args.get("endpoint")).trim();
            String transport = (ep.startsWith("http://") || ep.startsWith("https://")) ? "http" : "stdio";
            Map<String, Object> structured = new LinkedHashMap<>();
            structured.put("endpoint", ep);
            structured.put("transport", transport);
            return new Tool.Result(Json.stringify(structured), structured);
        });

        srv.registerResource(
                "passmcp://sdk/overview",
                "sdk-overview",
                "SDK Overview",
                "Overview of the passmcp SDK capabilities and supported MCP revisions.",
                "text/plain",
                uri -> "passmcp-sdk-java supports MCP 2026-07-28, 2025-11-25, and 2025-06-18.");

        srv.registerPrompt(
                "audit_summary",
                "Audit Summary Prompt",
                "Generate a concise audit summary prompt for a named MCP server.",
                List.of(new McpServer.PromptArgument(
                        "server_name", "Name of the MCP server being audited", true)),
                args -> "Summarize passmcp evaluation findings and remediation steps for "
                        + args.get("server_name") + ".");

        return srv;
    }

    /** Runs the reference server over {@code stdin}/{@code stdout} until EOF. */
    public static void main(String[] args) throws IOException {
        StdioServer.serveStdio(buildServer());
    }
}

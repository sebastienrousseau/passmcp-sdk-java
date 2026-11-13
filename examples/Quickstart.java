// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import com.satellion.passmcp.sdk.AttestationVerifier;
import com.satellion.passmcp.sdk.CacheHints;
import com.satellion.passmcp.sdk.McpClient;
import com.satellion.passmcp.sdk.McpServer;
import com.satellion.passmcp.sdk.OriginGuard;
import com.satellion.passmcp.sdk.Tool;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Runnable offline quickstart exercising server registration, stateless discovery,
 * SEP-2164/SEP-2549 conformance, read-only client policy, and attestation verification.
 */
public final class Quickstart {
    private Quickstart() {
    }

    /**
     * Runs the end-to-end offline quickstart.
     *
     * @param args unused CLI arguments
     * @throws Exception if verification fails
     */
    public static void main(String[] args) throws Exception {
        var srv = new McpServer("billing", "0.0.10")
                .setCacheHints(CacheHints.publicScope(30_000L))
                .setOriginGuard(new OriginGuard(List.of("https://console.example.com")));
        srv.registerTool(Tool.readOnly("health", "Read-only health probe"), callArgs -> "ok");
        srv.registerResource("mcp://billing/status", "status", "text/plain", uri -> "healthy");

        var st = AttestationVerifier.parse(Files.readString(Path.of("testdata/statement.json")));
        if (!st.covers("http", "https://mcp.example.com/mcp")) {
            throw new IllegalStateException("untrusted server");
        }

        var client = McpClient.forServer(srv)
                .requireAttestation(st, "http", "https://mcp.example.com/mcp");
        Map<String, Object> discovered = client.discover();
        String out = client.callTool("health", Map.of());
        System.out.println("quickstart ok: protocol=" + discovered.get("protocolVersion")
                + " health=" + out
                + " grade=" + st.scoreGrade());
    }
}

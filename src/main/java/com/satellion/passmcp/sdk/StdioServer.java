// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Newline-delimited UTF-8 JSON-RPC 2.0 server loop over standard input/output streams.
 *
 * <p>Never writes banners or diagnostic logs to {@code out}; notifications (frames without
 * {@code id}) produce no output frame, and malformed lines yield a single-line {@code -32700}
 * JSON-RPC error response without terminating the loop.
 */
public final class StdioServer {
    private StdioServer() {
    }

    /**
     * Serves {@code server} over {@link System#in} and {@link System#out} until EOF.
     *
     * @param server configured MCP server
     * @throws IOException if stream I/O fails
     */
    public static void serveStdio(McpServer server) throws IOException {
        serve(server, System.in, System.out);
    }

    /**
     * Serves {@code server} over arbitrary byte streams until {@code in} reaches EOF.
     *
     * @param server configured MCP server
     * @param in newline-delimited UTF-8 JSON-RPC input stream
     * @param out newline-delimited UTF-8 JSON-RPC output stream
     * @throws IOException if reading or flushing fails
     */
    public static void serve(McpServer server, InputStream in, OutputStream out) throws IOException {
        Objects.requireNonNull(server, "server");
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(out, "out");
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
        String line;
        while ((line = reader.readLine()) != null) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String reply = server.handleJson(trimmed);
            if (!reply.isEmpty()) {
                writer.write(reply);
                writer.write('\n');
                writer.flush();
            }
        }
    }
}

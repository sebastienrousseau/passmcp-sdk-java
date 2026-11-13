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
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/**
 * Client-side MCP {@code stdio} transport supporting both in-memory stream pairs
 * ({@link PipedInputStream}/{@link PipedOutputStream}) and spawned child processes
 * ({@link ProcessBuilder}).
 */
public final class StdioTransport implements Function<String, String>, AutoCloseable {
    private static final int PIPE_BUFFER_BYTES = 65_536;

    @FunctionalInterface
    private interface CloseHook {
        void onClose() throws IOException;
    }

    private final BufferedReader reader;
    private final BufferedWriter writer;
    private final CloseHook closeHook;
    private boolean closed;

    private StdioTransport(InputStream in, OutputStream out, CloseHook closeHook) {
        this.reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        this.writer = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
        this.closeHook = closeHook;
    }

    /**
     * Wraps an existing pair of streams connected to an MCP stdio server.
     *
     * @param serverStdout stream carrying single-line UTF-8 responses from the server
     * @param serverStdin stream accepting single-line UTF-8 requests for the server
     * @return client {@link StdioTransport}
     */
    public static StdioTransport fromStreams(InputStream serverStdout, OutputStream serverStdin) {
        Objects.requireNonNull(serverStdout, "serverStdout");
        Objects.requireNonNull(serverStdin, "serverStdin");
        return new StdioTransport(serverStdout, serverStdin, () -> {
            serverStdin.close();
            serverStdout.close();
        });
    }

    /**
     * Connects to an in-process {@link McpServer} over paired {@link PipedInputStream} and
     * {@link PipedOutputStream} buffers without binding any network port.
     *
     * @param server target MCP server
     * @return connected {@link StdioTransport}
     * @throws IOException if pipe creation fails
     */
    public static StdioTransport inMemory(McpServer server) throws IOException {
        Objects.requireNonNull(server, "server");
        PipedOutputStream clientOut = new PipedOutputStream();
        PipedInputStream serverIn = new PipedInputStream(clientOut, PIPE_BUFFER_BYTES);
        PipedOutputStream serverOut = new PipedOutputStream();
        PipedInputStream clientIn = new PipedInputStream(serverOut, PIPE_BUFFER_BYTES);
        Thread worker = new Thread(() -> runLoop(server, serverIn, serverOut), "passmcp-stdio-server");
        worker.setDaemon(true);
        worker.start();
        return new StdioTransport(clientIn, clientOut, () -> closeInMemory(clientOut, clientIn, worker));
    }

    /**
     * Spawns a child MCP server process and attaches to its {@code stdin}/{@code stdout} pipes.
     *
     * @param command argv command list (executable followed by arguments)
     * @return connected {@link StdioTransport}
     * @throws IOException if spawning the child process fails
     */
    public static StdioTransport spawn(List<String> command) throws IOException {
        if (command == null || command.isEmpty()) {
            throw new IllegalArgumentException("Stdio command must not be empty");
        }
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectError(ProcessBuilder.Redirect.DISCARD);
        Process proc = pb.start();
        return new StdioTransport(
                proc.getInputStream(),
                proc.getOutputStream(),
                () -> terminateChild(proc));
    }

    @Override
    public synchronized String apply(String rawJson) {
        if (closed) {
            throw new IllegalStateException("StdioTransport is closed");
        }
        if (rawJson == null || rawJson.indexOf('\n') >= 0 || rawJson.indexOf('\r') >= 0) {
            throw new IllegalArgumentException("Stdio JSON-RPC frame must be a single non-null line");
        }
        boolean expectsReply = hasRequestId(rawJson);
        try {
            writer.write(rawJson);
            writer.write('\n');
            writer.flush();
            if (!expectsReply) {
                return "";
            }
            String line = reader.readLine();
            if (line == null) {
                throw new IOException("Unexpected EOF from stdio MCP server");
            }
            return line;
        } catch (IOException ex) {
            throw new UncheckedIOException("Stdio transport I/O failure", ex);
        }
    }

    @Override
    public synchronized void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        closeHook.onClose();
    }

    private static boolean hasRequestId(String rawJson) {
        try {
            Object parsed = Json.parse(rawJson);
            return parsed instanceof Map<?, ?> map && map.containsKey("id");
        } catch (IllegalArgumentException ex) {
            return true;
        }
    }

    private static void runLoop(McpServer server, InputStream in, OutputStream out) {
        try (InputStream ownedIn = in; OutputStream ownedOut = out) {
            StdioServer.serve(server, ownedIn, ownedOut);
        } catch (IOException ignored) {
            // Pipe closed cleanly by client shutdown.
        }
    }

    private static void closeInMemory(OutputStream clientOut, InputStream clientIn, Thread worker)
            throws IOException {
        clientOut.close();
        try {
            worker.join(2_000L);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
        clientIn.close();
    }

    private static void terminateChild(Process proc) throws IOException {
        try {
            proc.getOutputStream().close();
        } catch (IOException ignored) {
            // Child may have already exited.
        }
        try {
            if (!proc.waitFor(2L, TimeUnit.SECONDS)) {
                proc.destroyForcibly();
                proc.waitFor(1L, TimeUnit.SECONDS);
            }
        } catch (InterruptedException ex) {
            proc.destroyForcibly();
            Thread.currentThread().interrupt();
        }
        proc.getInputStream().close();
    }
}

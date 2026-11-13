// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Conformance suites for Phase 2 transports ({@code stdio}, Streamable HTTP),
 * OAuth 2.1 + PKCE + RFC 9728 / RFC 8414 metadata validation, and schema enforcement.
 */
public final class Phase2TestSuite {
    private Phase2TestSuite() {
    }

    /** Child-process entrypoint used by {@link #testStdioSpawnChildProcess()} when invoked via {@code java}. */
    public static void main(String[] args) throws Exception {
        StdioServer.serveStdio(demoServer());
    }

    /** Executes all Phase 2 suites and returns the number of suites completed. */
    public static int runAll() throws Exception {
        testStdioFramingAndInMemoryPipes();
        testStdioSpawnChildProcess();
        testStreamableHttpProcessorAndClient();
        testHttpSessionLifecycle();
        testOAuthPkceAndBearerChallenge();
        testOAuthDiscoveryMetadataValidation();
        testSchemaValidationAndStructuredOutput();
        return 7;
    }

    private static void testStdioFramingAndInMemoryPipes() throws Exception {
        McpServer srv = demoServer();
        String frames = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n"
                + "{truncated-json\n"
                + "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        StdioServer.serve(srv, new ByteArrayInputStream(frames.getBytes(StandardCharsets.UTF_8)), out);
        String[] lines = out.toString(StandardCharsets.UTF_8).trim().split("\n");
        check(lines.length == 2, "notification omitted and malformed line + ping answered");
        Map<String, Object> parseErr = Json.parseObject(lines[0]);
        check(Json.reqInt(Json.asObject(parseErr.get("error"), "err"), "code") == -32700, "stdio -32700 recovery");
        Map<String, Object> pingOk = Json.parseObject(lines[1]);
        check(Json.reqInt(pingOk, "id") == 1, "stdio kept reading after malformed line");

        try (StdioTransport pipe = StdioTransport.inMemory(srv)) {
            McpClient client = new McpClient(pipe);
            Map<String, Object> init = client.initialize();
            check("2026-07-28".equals(init.get("protocolVersion")), "stdio in-memory initialize");
            Map<String, Object> disc = client.discover();
            check("discover".equals(disc.get("resultType")), "discover resultType");
            Map<String, Object> meta = Json.asObject(disc.get("_meta"), "_meta");
            Map<String, Object> info = Json.asObject(meta.get("io.modelcontextprotocol/serverInfo"), "serverInfo");
            check("demo".equals(info.get("name")), "discover _meta serverInfo");
            String res = client.callTool("inspect_target", Map.of("endpoint", "https://mcp.example.com/mcp"));
            check(res.contains("\"http\""), "stdio in-memory tool call");
        }
    }

    private static void testStdioSpawnChildProcess() throws Exception {
        String javaBin = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        String cp = System.getProperty("java.class.path");
        try (StdioTransport child = StdioTransport.spawn(
                List.of(javaBin, "-cp", cp, "com.satellion.passmcp.sdk.Phase2TestSuite"))) {
            McpClient client = new McpClient(child);
            client.initialize();
            client.ping();
            check(client.listTools().size() == 1, "child process listed 1 tool");
            check("overview-body".equals(client.readResource("passmcp://sdk/overview")), "child resource read");
        }
        if (Files.isDirectory(Path.of("target/example-classes"))) {
            try (StdioTransport ex = StdioTransport.spawn(
                    List.of(javaBin, "-cp", "target/classes:target/example-classes", "StdioServerExample"))) {
                McpClient client = new McpClient(ex);
                Map<String, Object> disc = client.discover();
                check("discover".equals(disc.get("resultType")), "StdioServerExample discover");
                String out = client.callTool("inspect_target", Map.of("endpoint", "https://example.com/mcp"));
                check(out.contains("https://example.com/mcp"), "StdioServerExample inspect_target");
            }
        }
    }

    private static void testStreamableHttpProcessorAndClient() {
        McpServer srv = demoServer()
                .setOriginGuard(new OriginGuard(List.of("https://app.example.com")));
        HttpProcessor proc = new HttpProcessor(srv)
                .requireBearerAuth("secret-tok"::equals, "https://mcp.example.com/.well-known/oauth-protected-resource");

        HttpProcessor.HttpResponse badOrigin = proc.handle(new HttpProcessor.HttpRequest(
                "POST", "/mcp", Map.of("Origin", "https://evil.example"), "{}"));
        check(badOrigin.status() == 403, "disallowed Origin -> 403");

        HttpProcessor.HttpResponse unauth = proc.handle(new HttpProcessor.HttpRequest(
                "POST", "/mcp", Map.of(), "{}"));
        check(unauth.status() == 401, "missing Bearer -> 401");
        OAuth.BearerChallenge chal = OAuth.parseBearerChallenge(unauth.header("WWW-Authenticate"));
        check("https://mcp.example.com/.well-known/oauth-protected-resource".equals(chal.resourceMetadata()),
                "401 carries RFC 9728 resource_metadata");

        Map<String, String> authHdr = Map.of("Authorization", "Bearer secret-tok");
        HttpProcessor.HttpResponse getResp = proc.handle(new HttpProcessor.HttpRequest("GET", "/mcp", authHdr, ""));
        check(getResp.status() == 405 && "POST".equals(getResp.header("Allow")), "GET -> 405 Allow: POST");

        HttpProcessor.HttpResponse badJson = proc.handle(new HttpProcessor.HttpRequest("POST", "/mcp", authHdr, "{bad"));
        check(badJson.status() == 400 && badJson.body().contains("-32700"), "malformed JSON -> 400 -32700");

        HttpProcessor.HttpResponse note = proc.handle(new HttpProcessor.HttpRequest(
                "POST", "/mcp", authHdr, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"));
        check(note.status() == 202 && note.body().isEmpty(), "notification -> 202 empty body");

        Map<String, String> mismatchHdr = Map.of(
                "Authorization", "Bearer secret-tok",
                "MCP-Protocol-Version", "2026-07-28",
                "MCP-Method", "tools/list");
        HttpProcessor.HttpResponse mismatch = proc.handle(new HttpProcessor.HttpRequest(
                "POST", "/mcp", mismatchHdr, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}"));
        check(mismatch.status() == 400 && mismatch.body().contains("-32020"), "MCP-Method mismatch -> 400 -32020");

        HttpProcessor.HttpResponse unknown = proc.handle(new HttpProcessor.HttpRequest(
                "POST", "/mcp", authHdr, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"sampling/createMessage\"}"));
        check(unknown.status() == 404 && unknown.body().contains("-32601"), "stateless -32601 -> 404");

        HttpTransport transport = HttpTransport.inMemory(proc)
                .setBearerToken("secret-tok")
                .setOrigin("https://app.example.com");
        McpClient client = new McpClient(transport);
        client.discover();
        String result = client.callTool("inspect_target", Map.of("endpoint", "stdio://local"));
        check(result.contains("\"stdio\""), "HttpTransport end-to-end tool call");
        check(proc.toJdkHttpHandler() != null, "JDK HttpHandler adapter created");
    }

    private static void testHttpSessionLifecycle() {
        McpServer sessionSrv = new McpServer("sess", "0.0.10", McpServer.REVISION_2025_11_25);
        sessionSrv.registerTool(Tool.readOnly("ping_tool", "Read-only session tool"), args -> "pong");
        HttpProcessor proc = new HttpProcessor(sessionSrv).enableSessions(true);

        HttpProcessor.HttpResponse noSess = proc.handle(new HttpProcessor.HttpRequest(
                "POST", "/mcp", Map.of(), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}"));
        check(noSess.status() == 404, "missing Mcp-Session-Id -> 404");

        HttpTransport transport = HttpTransport.inMemory(proc).setStatelessHeaders(false);
        McpClient client = new McpClient(transport);
        client.initialize();
        check(transport.sessionId() != null && !transport.sessionId().isEmpty(), "Mcp-Session-Id issued");
        check("pong".equals(client.callTool("ping_tool", Map.of())), "subsequent request carries Mcp-Session-Id");

        transport.setSessionId("forged-session");
        boolean rejected = false;
        try {
            client.ping();
        } catch (IllegalStateException ex) {
            rejected = ex.getMessage().contains("404");
        }
        check(rejected, "unknown Mcp-Session-Id rejected with 404");
    }

    private static void testOAuthPkceAndBearerChallenge() {
        String rfcVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        check(rfcChallenge.equals(OAuth.computeS256Challenge(rfcVerifier)), "RFC 7636 Appendix B S256 vector");
        check(OAuth.verifyS256(rfcVerifier, rfcChallenge), "verifyS256 accepts RFC vector");
        check(!OAuth.verifyS256(rfcVerifier, rfcChallenge + "x"), "verifyS256 rejects mismatch");

        String generated = OAuth.generateVerifier();
        check(generated.length() == 64, "default PKCE verifier length 64");
        check(OAuth.verifyS256(generated, OAuth.computeS256Challenge(generated)), "generated PKCE round-trip");
        expectIllegalArg(() -> OAuth.generateVerifier(42), "verifier < 43 rejected");
        expectIllegalArg(() -> OAuth.generateVerifier(129), "verifier > 128 rejected");

        String hdr = OAuth.buildBearerChallenge(
                "https://mcp.example.com/.well-known/oauth-protected-resource",
                "mcp:read mcp:tools",
                "invalid_token",
                "Token expired");
        OAuth.BearerChallenge parsed = OAuth.parseBearerChallenge(hdr);
        check("mcp:read mcp:tools".equals(parsed.scope()), "Bearer scope round-trip");
        check("invalid_token".equals(parsed.error()), "Bearer error round-trip");
        check("Token expired".equals(parsed.errorDescription()), "Bearer error_description round-trip");
    }

    private static void testOAuthDiscoveryMetadataValidation() {
        List<String> prmUrls = OAuth.protectedResourceWellKnownUrls("https://mcp.example.com/mcp");
        check(prmUrls.size() == 2, "path resource yields 2 RFC 9728 candidate URLs");
        check("https://mcp.example.com/.well-known/oauth-protected-resource/mcp".equals(prmUrls.get(0)),
                "path-suffixed RFC 9728 URL first");
        check("https://mcp.example.com/.well-known/oauth-protected-resource".equals(prmUrls.get(1)),
                "root RFC 9728 URL second");

        String validPrm = "{\"resource\":\"https://mcp.example.com/mcp\","
                + "\"authorization_servers\":[\"https://auth.example.com\"],"
                + "\"scopes_supported\":[\"mcp:read\"]}";
        OAuth.ProtectedResourceMetadata prm = OAuth.validateProtectedResourceMetadata(
                validPrm, "https://mcp.example.com/mcp");
        check(prm.authorizationServers().contains("https://auth.example.com"), "valid RFC 9728 metadata");
        expectIllegalArg(() -> OAuth.validateProtectedResourceMetadata(
                validPrm, "https://other.example.com/mcp"), "RFC 9728 resource mismatch rejected");

        check("https://auth.example.com/.well-known/oauth-authorization-server/tenant"
                .equals(OAuth.authorizationServerWellKnownUrl("https://auth.example.com/tenant")),
                "RFC 8414 tenant well-known URL");
        String validAs = "{\"issuer\":\"https://auth.example.com\","
                + "\"authorization_endpoint\":\"https://auth.example.com/authorize\","
                + "\"token_endpoint\":\"https://auth.example.com/token\","
                + "\"code_challenge_methods_supported\":[\"S256\"]}";
        OAuth.AuthorizationServerMetadata asMeta = OAuth.validateAuthorizationServerMetadata(
                validAs, "https://auth.example.com");
        check(asMeta.codeChallengeMethodsSupported().contains("S256"), "RFC 8414 S256 verified");

        String plainOnly = validAs.replace("\"S256\"", "\"plain\"");
        expectIllegalArg(() -> OAuth.validateAuthorizationServerMetadata(plainOnly, null),
                "RFC 8414 without S256 rejected");
    }

    private static void testSchemaValidationAndStructuredOutput() {
        McpClient client = McpClient.forServer(demoServer());
        Map<String, Object> callRes = client.rpc("tools/call", Map.of(
                "name", "inspect_target",
                "arguments", Map.of("endpoint", "https://mcp.example.com/mcp")));
        Map<String, Object> structured = Json.asObject(callRes.get("structuredContent"), "structuredContent");
        check("http".equals(structured.get("transport")), "structuredContent emitted on tools/call");

        expectRpcCode(() -> client.rpc("tools/call", Map.of("name", "inspect_target", "arguments", Map.of())),
                -32602, "missing required tool argument");
        expectRpcCode(() -> client.rpc("tools/call", Map.of(
                "name", "inspect_target", "arguments", Map.of("endpoint", Integer.valueOf(42)))),
                -32602, "wrong tool argument type");
        expectRpcCode(() -> client.rpc("tools/call", Map.of(
                "name", "inspect_target", "arguments", Map.of("endpoint", "ok", "extra", "no"))),
                -32602, "additionalProperties: false enforced");
        expectRpcCode(() -> client.rpc("prompts/get", Map.of("name", "audit_summary", "arguments", Map.of())),
                -32602, "missing required prompt argument");
    }

    private static McpServer demoServer() {
        McpServer srv = new McpServer("demo", "0.0.10")
                .setInstructions("Demo instructions")
                .setCacheHints(CacheHints.ofSeconds(true, 300L, "public"));
        Map<String, Object> inSchema = new LinkedHashMap<>();
        inSchema.put("type", "object");
        inSchema.put("additionalProperties", Boolean.FALSE);
        inSchema.put("required", List.of("endpoint"));
        inSchema.put("properties", Map.of("endpoint", Map.of("type", "string")));
        Map<String, Object> outSchema = Map.of(
                "type", "object",
                "required", List.of("endpoint", "transport"),
                "properties", Map.of("endpoint", Map.of("type", "string"), "transport", Map.of("type", "string")));
        Tool inspect = Tool.builder("inspect_target", "Inspect target endpoint transport safely without side effects.")
                .title("Inspect MCP Target")
                .inputSchema(inSchema)
                .outputSchema(outSchema)
                .build();
        srv.registerStructuredTool(inspect, args -> {
            String ep = (String) args.get("endpoint");
            String tr = ep.startsWith("https://") ? "http" : "stdio";
            Map<String, Object> sc = Map.of("endpoint", ep, "transport", tr);
            return new Tool.Result(Json.stringify(sc), sc);
        });
        srv.registerResource("passmcp://sdk/overview", "sdk-overview", "SDK Overview",
                "SDK overview resource.", "text/plain", uri -> "overview-body");
        srv.registerPrompt("audit_summary", "Audit Summary", "Summarize audit.",
                List.of(new McpServer.PromptArgument("server_name", "Server name", true)),
                args -> "Audit " + args.get("server_name"));
        return srv;
    }

    private static void expectIllegalArg(Runnable fn, String label) {
        try {
            fn.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Expected IllegalArgumentException for " + label);
    }

    private static void expectRpcCode(Runnable fn, int code, String label) {
        try {
            fn.run();
        } catch (McpClient.RpcException ex) {
            check(ex.code() == code, label + " code=" + ex.code());
            return;
        }
        throw new AssertionError("Expected RpcException(" + code + ") for " + label);
    }

    private static void check(boolean cond, String label) {
        if (!cond) {
            throw new AssertionError("Assertion failed: " + label);
        }
    }
}

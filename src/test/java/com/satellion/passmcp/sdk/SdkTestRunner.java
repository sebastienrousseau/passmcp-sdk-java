// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Offline zero-dependency test runner verifying JSON parsing, attestation verification,
 * capability gating, SEP-2164, SEP-2549, OriginGuard, and read-only client Policy.
 */
public final class SdkTestRunner {
    private SdkTestRunner() {
    }

    /**
     * Entrypoint for {@code make test}.
     *
     * @param args unused CLI arguments
     * @throws Exception on any test failure
     */
    public static void main(String[] args) throws Exception {
        int passed = runAll();
        System.out.println("passmcp-sdk-java: " + passed + " test suites passed");
    }

    /**
     * Executes every SDK conformance and tamper test suite.
     *
     * @return number of suites executed
     * @throws Exception on any failure
     */
    public static int runAll() throws Exception {
        String fixture = Files.readString(Path.of("testdata/statement.json"));
        testJsonRoundTripAndBounds();
        testValidFixtureAndSha512(fixture);
        testAttestationEnvelopeAndSubjectTampering(fixture);
        testAttestationPredicateAndCountsTampering(fixture);
        testCapabilityGatingAndDiscover();
        testSep2164ResourceErrors();
        testSep2549CacheHints();
        testOriginGuardAndNotifications();
        testClientPolicyAndPrompts();
        int phase2 = Phase2TestSuite.runAll();
        return 9 + phase2;
    }

    private static void testJsonRoundTripAndBounds() {
        Map<String, Object> src = new LinkedHashMap<>();
        src.put("str", "hello\n\"world\"\u0007");
        src.put("num", Long.valueOf(42L));
        src.put("flt", Double.valueOf(-3.5e2));
        src.put("arr", List.of(Boolean.TRUE, Boolean.FALSE));
        String wire = Json.stringify(src);
        Map<String, Object> parsed = Json.parseObject(wire);
        check("hello\n\"world\"\u0007".equals(parsed.get("str")), "escaped string round-trip");
        check(Json.reqInt(parsed, "num") == 42, "integer round-trip");
        check(Json.reqDouble(parsed, "flt") == -350.0, "float round-trip");

        expectIllegalArg(() -> Json.parse("{bad}"), "unquoted key");
        expectIllegalArg(() -> Json.parse("{\"a\":1} trailing"), "trailing garbage");
        expectIllegalArg(() -> Json.parse("01"), "leading zero");
        expectIllegalArg(() -> Json.parse("\"raw\nnewline\""), "unescaped control char");
        expectIllegalArg(() -> Json.parse("{\"a\":1,}"), "trailing comma");
    }

    private static void testValidFixtureAndSha512(String fixture) {
        Statement st = AttestationVerifier.parse(fixture);
        check(st.covers("http", "https://mcp.example.com/mcp"), "fixture covers exact target");
        check(st.covers("http", "  https://mcp.example.com/mcp  "), "covers trims endpoint");
        check(!st.covers("stdio", "https://mcp.example.com/mcp"), "wrong transport rejected");
        check(!st.covers("http", "https://evil.example.com/mcp"), "wrong endpoint rejected");
        check(Double.valueOf(88.0).equals(st.scoreTotal()), "scoreTotal == 88");
        check("B".equals(st.scoreGrade()), "scoreGrade == B");
        Statement.Verdict origin = st.verdictFor("protocol.origin").orElseThrow();
        check("fail".equals(origin.status()) && "major".equals(origin.severity()), "verdict lookup");
        check(st.verdictFor("nonexistent.check").isEmpty(), "missing check is empty");

        String desc = "http\nhttps://mcp.example.com/mcp";
        String sha512 = AttestationVerifier.sha512Hex(desc);
        Map<String, Object> root = Json.parseObject(fixture);
        Map<String, Object> sub0 = firstSubject(root);
        sub0.put("digest", Map.of("sha512", sha512));
        Statement st512 = AttestationVerifier.parse(Json.stringify(root));
        check(st512.covers("http", "https://mcp.example.com/mcp"), "sha512-only covers target");

        Map<String, String> both = new LinkedHashMap<>();
        both.put("sha256", AttestationVerifier.sha256Hex(desc));
        both.put("sha512", "00" + sha512.substring(2));
        sub0.put("digest", both);
        expectIllegalArg(() -> AttestationVerifier.parse(Json.stringify(root)), "bad sha512 alongside sha256");
    }

    private static void testAttestationEnvelopeAndSubjectTampering(String fixture) {
        expectTamperFails(fixture, root -> root.put("_type", "https://in-toto.io/Statement/v0.1"), "wrong _type");
        expectTamperFails(fixture, root -> root.put("predicateType", "https://example.com/other"), "wrong predicateType");
        expectTamperFails(fixture, root -> root.put("subject", List.of()), "zero subjects");
        expectTamperFails(fixture, root -> {
            Object s = firstSubject(root);
            root.put("subject", List.of(s, s));
        }, "two subjects");
        expectTamperFails(fixture, root -> firstSubject(root).put("name", "https://other.example.com/mcp"),
                "subject name mismatch");
        expectTamperFails(fixture, root -> firstSubject(root).put("digest", Map.of("md5", "abcd")),
                "unknown digest algorithm only");
        expectTamperFails(fixture, root -> {
            String upper = AttestationVerifier.sha256Hex("http\nhttps://mcp.example.com/mcp").toUpperCase();
            firstSubject(root).put("digest", Map.of("sha256", upper));
        }, "uppercase hex digest rejected");
    }

    private static void testAttestationPredicateAndCountsTampering(String fixture) {
        expectTamperFails(fixture, root -> predicate(root).put("subjectKind", "artifact"), "wrong subjectKind");
        expectTamperFails(fixture, root -> childObject(predicate(root), "target").put("transport", "grpc"),
                "unknown transport");
        expectTamperFails(fixture, root -> childObject(predicate(root), "target").put("endpoint", "   "),
                "empty endpoint");
        expectTamperFails(fixture, root -> childObject(predicate(root), "instrument").put("version", ""),
                "empty instrument version");
        expectTamperFails(fixture, root -> predicate(root).put("ranAt", "0001-01-01T00:00:00Z"),
                "zero timestamp");
        expectTamperFails(fixture, root -> predicate(root).put("verdicts", List.of()), "empty verdicts");
        expectTamperFails(fixture, root -> childObject(predicate(root), "judgedAgainst")
                .put("checkInventory", ""), "empty checkInventory");
        expectTamperFails(fixture, root -> childObject(predicate(root), "judgedAgainst")
                .put("rubric", ""), "score without rubric");
        expectTamperFails(fixture, root -> childObject(predicate(root), "counts").put("pass", 99),
                "mismatched counts");

        Map<String, Object> noScore = Json.parseObject(fixture);
        predicate(noScore).remove("score");
        childObject(predicate(noScore), "judgedAgainst").put("rubric", "");
        Statement st = AttestationVerifier.parse(Json.stringify(noScore));
        check(st.scoreTotal() == null && st.scoreGrade() == null, "scoreless statement allowed without rubric");
    }

    private static void testCapabilityGatingAndDiscover() {
        McpServer bare = new McpServer("bare", "0.0.10");
        McpClient client = McpClient.forServer(bare);
        Map<String, Object> init = client.initialize();
        Map<String, Object> caps = Json.asObject(init.get("capabilities"), "capabilities");
        check(caps.isEmpty(), "undeclared capabilities omitted");
        client.ping();

        expectRpcCode(() -> client.rpc("tools/list", Map.of()), -32601, "undeclared tools/list");
        expectRpcCode(() -> client.rpc("tools/call", Map.of("name", "x")), -32601, "undeclared tools/call");
        expectRpcCode(() -> client.rpc("resources/list", Map.of()), -32601, "undeclared resources/list");
        expectRpcCode(() -> client.rpc("resources/templates/list", Map.of()), -32601, "undeclared templates/list");
        expectRpcCode(() -> client.rpc("resources/read", Map.of("uri", "mcp://x")), -32601, "undeclared resources/read");
        expectRpcCode(() -> client.rpc("prompts/list", Map.of()), -32601, "undeclared prompts/list");
        expectRpcCode(() -> client.rpc("prompts/get", Map.of("name", "p")), -32601, "undeclared prompts/get");

        bare.registerTool(Tool.readOnly("echo", "Echo probe"), args -> "pong");
        Map<String, Object> disc = client.discover();
        check("2026-07-28".equals(disc.get("protocolVersion")), "discover protocolVersion");
        check(Json.asObject(disc.get("capabilities"), "caps").containsKey("tools"), "tools capability declared");
        check(!Json.asArray(disc.get("tools"), "tools").isEmpty(), "discover includes declared tools catalog");
    }

    private static void testSep2164ResourceErrors() {
        McpServer modern = new McpServer("res", "0.0.10", McpServer.REVISION_2026_07_28);
        modern.registerResource("mcp://docs/readme", "readme", "text/plain", uri -> "hello");
        McpClient modernClient = McpClient.forServer(modern);
        check("hello".equals(modernClient.readResource("mcp://docs/readme")), "read registered resource");

        McpClient.RpcException err2026 = expectRpcCode(
                () -> modernClient.readResource("mcp://docs/missing"), -32602, "SEP-2164 -32602 on 2026-07-28");
        check("mcp://docs/missing".equals(err2026.data().get("uri")), "SEP-2164 echoes error.data.uri");

        McpServer legacy = new McpServer("res", "0.0.10", McpServer.REVISION_2025_11_25);
        legacy.registerResourceTemplate("mcp://docs/{name}", "doc-tpl", "text/plain");
        McpClient legacyClient = McpClient.forServer(legacy);
        legacyClient.initialize();
        McpClient.RpcException errLegacy = expectRpcCode(
                () -> legacyClient.readResource("mcp://docs/missing"), -32002, "-32002 on 2025-11-25");
        check("mcp://docs/missing".equals(errLegacy.data().get("uri")), "legacy error.data.uri");
    }

    private static void testSep2549CacheHints() {
        expectIllegalArg(() -> new CacheHints(-1L, "public"), "negative ttlMs rejected");
        expectIllegalArg(() -> new CacheHints(0L, "shared"), "invalid cacheScope rejected");

        McpServer srv = new McpServer("cached", "0.0.10")
                .setCacheHints(CacheHints.publicScope(15_000L));
        srv.registerTool(Tool.readOnly("t", "tool"), args -> "ok");
        srv.registerResource("mcp://r/1", "r1", "text/plain", uri -> "v");
        srv.registerPrompt("p", "prompt", args -> "hi");

        McpClient client = McpClient.forServer(srv);
        for (String method : List.of("tools/list", "resources/list", "resources/templates/list", "prompts/list")) {
            Map<String, Object> res = client.rpc(method, Map.of());
            CacheHints hints = CacheHints.fromMetaMap(Json.asObject(res.get("_meta"), "_meta"));
            check(hints.ttlMs() == 15_000L && "public".equals(hints.cacheScope()), "SEP-2549 _meta on " + method);
        }

        McpServer v2025 = new McpServer("legacy", "0.0.10", McpServer.REVISION_2025_06_18);
        v2025.registerTool(Tool.readOnly("t", "tool"), args -> "ok");
        Map<String, Object> legacyList = McpClient.forServer(v2025).rpc("tools/list", Map.of());
        check(!legacyList.containsKey("_meta"), "pre-2026-07-28 omits SEP-2549 _meta");
    }

    private static void testOriginGuardAndNotifications() {
        expectIllegalArg(() -> new OriginGuard(List.of("*")), "wildcard origin rejected");
        expectIllegalArg(() -> new OriginGuard(List.of("null")), "null literal origin rejected");

        OriginGuard guard = new OriginGuard(List.of("https://app.example.com/"));
        McpServer srv = new McpServer("http-srv", "0.0.10").setOriginGuard(guard);
        String pingReq = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";
        String initNote = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";

        check(srv.handleHttp(null, pingReq).status() == 200, "absent Origin allowed");
        check(srv.handleHttp("https://app.example.com", pingReq).status() == 200, "allowlisted Origin allowed");
        check(srv.handleHttp("https://passmcp-origin-probe.invalid", pingReq).status() == 403,
                "foreign Origin refused with 403");
        check(srv.handleHttp("null", pingReq).status() == 403, "Origin: null refused with 403");
        McpServer.HttpReply ack = srv.handleHttp(null, initNote);
        check(ack.status() == 202 && ack.body().isEmpty(), "notification answered with 202 and empty body");
    }

    private static void testClientPolicyAndPrompts() {
        AtomicInteger mutationsRun = new AtomicInteger(0);
        McpServer srv = new McpServer("ops", "0.0.10");
        srv.registerTool(Tool.readOnly("status", "Read status"), args -> "green");
        srv.registerTool(Tool.mutating("drop", "Drop table", true), args -> {
            mutationsRun.incrementAndGet();
            return "dropped";
        });
        srv.registerTool(Tool.unannotated("mystery", "Unannotated tool"), args -> {
            mutationsRun.incrementAndGet();
            return "ran";
        });
        srv.registerPrompt("greet", "Greeting prompt", args -> "Hello " + args.getOrDefault("who", "world"));

        McpClient safeClient = McpClient.forServer(srv);
        check("green".equals(safeClient.callTool("status", Map.of())), "readOnly tool permitted");
        expectSecurity(() -> safeClient.callTool("drop", Map.of()), "mutating tool refused by default");
        expectSecurity(() -> safeClient.callTool("mystery", Map.of()), "unannotated tool refused by default");
        check(mutationsRun.get() == 0, "refused tools never invoked on server");

        McpClient mutClient = new McpClient(srv::handleJson, Policy.allowingMutations());
        check("dropped".equals(mutClient.callTool("drop", Map.of())), "explicit opt-in permits mutation");
        check(mutationsRun.get() == 1, "mutating handler invoked once");

        Map<String, Object> promptRes = safeClient.rpc(
                "prompts/get", Map.of("name", "greet", "arguments", Map.of("who", "mcp")));
        List<Object> msgs = Json.asArray(promptRes.get("messages"), "messages");
        Map<String, Object> msg0 = Json.asObject(msgs.get(0), "messages[0]");
        Map<String, Object> content = Json.asObject(msg0.get("content"), "content");
        check("Hello mcp".equals(content.get("text")), "prompts/get rendered message");
    }

    private static Map<String, Object> firstSubject(Map<String, Object> root) {
        List<Object> subs = Json.asArray(root.get("subject"), "subject");
        Map<String, Object> sub0 = Json.asObject(subs.get(0), "subject[0]");
        root.put("subject", List.of(sub0));
        return sub0;
    }

    private static Map<String, Object> predicate(Map<String, Object> root) {
        return childObject(root, "predicate");
    }

    private static Map<String, Object> childObject(Map<String, Object> parent, String key) {
        Map<String, Object> child = Json.asObject(parent.get(key), key);
        parent.put(key, child);
        return child;
    }

    private static void expectTamperFails(
            String fixture,
            java.util.function.Consumer<Map<String, Object>> mutator,
            String label) {
        Map<String, Object> root = Json.parseObject(fixture);
        mutator.accept(root);
        expectIllegalArg(() -> AttestationVerifier.parse(Json.stringify(root)), label);
    }

    private static void expectIllegalArg(Runnable fn, String label) {
        try {
            fn.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Expected IllegalArgumentException for: " + label);
    }

    private static void expectSecurity(Runnable fn, String label) {
        try {
            fn.run();
        } catch (SecurityException expected) {
            return;
        }
        throw new AssertionError("Expected SecurityException for: " + label);
    }

    private static McpClient.RpcException expectRpcCode(Runnable fn, int expectedCode, String label) {
        try {
            fn.run();
        } catch (McpClient.RpcException ex) {
            check(ex.code() == expectedCode, label + " (got " + ex.code() + ", want " + expectedCode + ")");
            return ex;
        }
        throw new AssertionError("Expected RpcException(" + expectedCode + ") for: " + label);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError("Assertion failed: " + message);
        }
    }
}

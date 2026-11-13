// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Offline verifier for {@code in-toto} {@code Statement/v1} attestations carrying
 * {@code https://satellion.com/attestation/mcp-evaluation/v1}.
 */
public final class AttestationVerifier {
    private static final Instant GO_ZERO_TIME = Instant.parse("0001-01-01T00:00:00Z");

    private AttestationVerifier() {
    }

    /**
     * Parses and strictly validates an attestation JSON document offline.
     *
     * @param jsonText raw JSON statement bytes as UTF-8 text
     * @return verified {@link Statement}
     */
    public static Statement parse(String jsonText) {
        Map<String, Object> root = Json.parseObject(jsonText);
        String type = strOrEmpty(root, "_type");
        String predicateType = strOrEmpty(root, "predicateType");
        List<Statement.Subject> subjects = parseSubjects(root.get("subject"));
        Map<String, Object> pred = Json.asObject(root.get("predicate"), "predicate");
        Statement statement = buildStatement(type, subjects, predicateType, pred);
        validate(statement);
        return statement;
    }

    /**
     * Reads, parses, and validates an attestation statement file from disk.
     *
     * @param path path to the JSON statement file
     * @return verified {@link Statement}
     * @throws IOException if the file cannot be read
     */
    public static Statement parseFile(Path path) throws IOException {
        return parse(Files.readString(path, StandardCharsets.UTF_8));
    }

    /**
     * Validates every structural, digest, basis, and count invariant on {@code st}.
     *
     * @param st statement to validate
     */
    public static void validate(Statement st) {
        List<String> problems = new ArrayList<>();
        validateEnvelope(st, problems);
        validateSubject(st, problems);
        validatePredicateMeta(st, problems);
        validateBasisAndScore(st, problems);
        validateVerdictsAndCounts(st, problems);
        if (!problems.isEmpty()) {
            throw new IllegalArgumentException("attestation: " + String.join("; ", problems));
        }
    }

    /**
     * Builds the canonical UTF-8 target descriptor {@code transport + "\n" + endpoint.trim()}.
     *
     * @param transport transport identifier
     * @param endpoint server URL or command line
     * @return canonical target descriptor string
     */
    public static String targetDescriptor(String transport, String endpoint) {
        return transport + "\n" + endpoint.trim();
    }

    /**
     * Computes lowercase SHA-256 hex over UTF-8 bytes of {@code value}.
     *
     * @param value input string
     * @return 64-character lowercase hex digest
     */
    public static String sha256Hex(String value) {
        return digestHex("SHA-256", value);
    }

    /**
     * Computes lowercase SHA-512 hex over UTF-8 bytes of {@code value}.
     *
     * @param value input string
     * @return 128-character lowercase hex digest
     */
    public static String sha512Hex(String value) {
        return digestHex("SHA-512", value);
    }

    static boolean coversDescriptor(Map<String, String> digestSet, String descriptor) {
        String mismatch = checkDigests(digestSet, descriptor);
        return "OK".equals(mismatch);
    }

    private static String checkDigests(Map<String, String> digestSet, String descriptor) {
        if (digestSet == null || digestSet.isEmpty()) {
            return "NONE";
        }
        boolean found = false;
        String sha256 = digestSet.get("sha256");
        if (sha256 != null) {
            found = true;
            if (!sha256.equals(sha256Hex(descriptor))) {
                return "sha256";
            }
        }
        String sha512 = digestSet.get("sha512");
        if (sha512 != null) {
            found = true;
            if (!sha512.equals(sha512Hex(descriptor))) {
                return "sha512";
            }
        }
        return found ? "OK" : "NONE";
    }

    private static void validateEnvelope(Statement st, List<String> problems) {
        if (!Statement.STATEMENT_TYPE.equals(st.type())) {
            problems.add("_type is \"" + st.type() + "\", want \"" + Statement.STATEMENT_TYPE + "\"");
        }
        if (!Statement.PREDICATE_TYPE.equals(st.predicateType())) {
            problems.add("predicateType is \"" + st.predicateType() + "\", want \"" + Statement.PREDICATE_TYPE + "\"");
        }
    }

    private static void validateSubject(Statement st, List<String> problems) {
        int count = st.subjects().size();
        if (count == 0) {
            problems.add("no subject: the statement is about nothing");
            return;
        }
        if (count != 1) {
            problems.add(count + " subjects: a passmcp evaluation is about one server");
            return;
        }
        Statement.Subject sub = st.subjects().get(0);
        String want = st.target().endpoint().trim();
        String subName = sub.name().trim();
        if (subName.isEmpty()) {
            problems.add("the subject has no name");
        } else if (!subName.equals(want)) {
            problems.add("the subject is named \"" + sub.name() + "\" but the predicate is about \"" + want + "\"");
        }
        String descriptor = targetDescriptor(st.target().transport(), st.target().endpoint());
        String status = checkDigests(sub.digest(), descriptor);
        if ("NONE".equals(status)) {
            problems.add("the subject has no sha256 or sha512 digest");
        } else if (!"OK".equals(status)) {
            problems.add("the subject " + status + " digest does not cover the target it names");
        }
    }

    private static void validatePredicateMeta(Statement st, List<String> problems) {
        if (!Statement.SUBJECT_KIND_DESCRIPTOR.equals(st.subjectKind())) {
            problems.add("subjectKind is \"" + st.subjectKind() + "\", want \"" + Statement.SUBJECT_KIND_DESCRIPTOR + "\"");
        }
        if (st.target().endpoint().trim().isEmpty()) {
            problems.add("the target has no endpoint");
        }
        String transport = st.target().transport();
        if (!"http".equals(transport) && !"stdio".equals(transport)) {
            problems.add("invalid or missing transport \"" + transport + "\"");
        }
        if (st.instrument().name().isEmpty() || st.instrument().version().isEmpty()) {
            problems.add("the instrument is not identified");
        }
        if (!isValidRunTimestamp(st.ranAt())) {
            problems.add("no valid run time");
        }
        if (st.verdicts().isEmpty()) {
            problems.add("no verdicts");
        }
    }

    private static boolean isValidRunTimestamp(String ranAt) {
        if (ranAt == null || ranAt.trim().isEmpty()) {
            return false;
        }
        try {
            Instant instant = OffsetDateTime.parse(ranAt).toInstant();
            return !GO_ZERO_TIME.equals(instant);
        } catch (DateTimeParseException ex) {
            return false;
        }
    }

    private static void validateBasisAndScore(Statement st, List<String> problems) {
        if (st.judgedAgainst().checkInventory().isEmpty()) {
            problems.add("judgedAgainst.checkInventory is empty");
        }
        if (st.score().isPresent() && st.judgedAgainst().rubric().isEmpty()) {
            problems.add("a score with no rubric version");
        }
    }

    private static void validateVerdictsAndCounts(Statement st, List<String> problems) {
        int pass = 0;
        int warn = 0;
        int fail = 0;
        int skip = 0;
        int info = 0;
        for (int i = 0; i < st.verdicts().size(); i++) {
            Statement.Verdict v = st.verdicts().get(i);
            if (v.id().isEmpty()) {
                problems.add("verdict " + i + " has no id");
                continue;
            }
            switch (v.status()) {
                case "pass" -> pass++;
                case "warn" -> warn++;
                case "fail" -> fail++;
                case "skip" -> skip++;
                case "info" -> info++;
                default -> problems.add("verdict " + v.id() + " has unknown status \"" + v.status() + "\"");
            }
        }
        Statement.Counts tallied = new Statement.Counts(pass, warn, fail, skip, info);
        if (!st.verdicts().isEmpty() && !tallied.equals(st.counts())) {
            problems.add("the counts disagree with the verdicts");
        }
    }

    private static Statement buildStatement(
            String type,
            List<Statement.Subject> subjects,
            String predicateType,
            Map<String, Object> pred) {
        Statement.Target target = parseTarget(pred.get("target"));
        Statement.Basis basis = parseBasis(pred.get("judgedAgainst"));
        Statement.Instrument instrument = parseInstrument(pred.get("instrument"));
        List<Statement.Verdict> verdicts = parseVerdicts(pred.get("verdicts"));
        Statement.Counts counts = parseCounts(pred.get("counts"));
        Statement.Score score = parseScore(pred.get("score"));
        return new Statement(
                type,
                subjects,
                predicateType,
                strOrEmpty(pred, "subjectKind"),
                target,
                basis,
                instrument,
                strOrEmpty(pred, "ranAt"),
                strOrEmpty(pred, "took"),
                verdicts,
                counts,
                score);
    }

    private static List<Statement.Subject> parseSubjects(Object raw) {
        if (raw == null) {
            return List.of();
        }
        List<Object> items = Json.asArray(raw, "subject");
        List<Statement.Subject> out = new ArrayList<>(items.size());
        for (Object item : items) {
            Map<String, Object> obj = Json.asObject(item, "subject[]");
            Map<String, String> digests = parseDigestMap(obj.get("digest"));
            out.add(new Statement.Subject(strOrEmpty(obj, "name"), digests));
        }
        return out;
    }

    private static Map<String, String> parseDigestMap(Object raw) {
        if (raw == null) {
            return Map.of();
        }
        Map<String, Object> obj = Json.asObject(raw, "subject.digest");
        Map<String, String> out = new LinkedHashMap<>(obj.size());
        for (Map.Entry<String, Object> entry : obj.entrySet()) {
            if (!(entry.getValue() instanceof String s)) {
                throw new IllegalArgumentException("Expected string digest for " + entry.getKey());
            }
            out.put(entry.getKey(), s);
        }
        return out;
    }

    private static Statement.Target parseTarget(Object raw) {
        if (raw == null) {
            return new Statement.Target("", "");
        }
        Map<String, Object> obj = Json.asObject(raw, "predicate.target");
        return new Statement.Target(strOrEmpty(obj, "transport"), strOrEmpty(obj, "endpoint"));
    }

    private static Statement.Basis parseBasis(Object raw) {
        if (raw == null) {
            return new Statement.Basis("", "", "");
        }
        Map<String, Object> obj = Json.asObject(raw, "predicate.judgedAgainst");
        return new Statement.Basis(
                strOrEmpty(obj, "specRevision"),
                strOrEmpty(obj, "rubric"),
                strOrEmpty(obj, "checkInventory"));
    }

    private static Statement.Instrument parseInstrument(Object raw) {
        if (raw == null) {
            return new Statement.Instrument("", "", 0);
        }
        Map<String, Object> obj = Json.asObject(raw, "predicate.instrument");
        return new Statement.Instrument(
                strOrEmpty(obj, "name"),
                strOrEmpty(obj, "version"),
                Json.optInt(obj, "reportSchemaVersion", 0));
    }

    private static List<Statement.Verdict> parseVerdicts(Object raw) {
        if (raw == null) {
            return List.of();
        }
        List<Object> items = Json.asArray(raw, "predicate.verdicts");
        List<Statement.Verdict> out = new ArrayList<>(items.size());
        for (Object item : items) {
            Map<String, Object> obj = Json.asObject(item, "verdict");
            out.add(new Statement.Verdict(
                    strOrEmpty(obj, "id"),
                    strOrEmpty(obj, "phase"),
                    strOrEmpty(obj, "status"),
                    Json.optString(obj, "severity"),
                    parseStringList(obj.get("evidence")),
                    Json.optString(obj, "doc")));
        }
        return out;
    }

    private static List<String> parseStringList(Object raw) {
        if (raw == null) {
            return List.of();
        }
        List<Object> items = Json.asArray(raw, "evidence");
        List<String> out = new ArrayList<>(items.size());
        for (Object item : items) {
            if (!(item instanceof String s)) {
                throw new IllegalArgumentException("Expected string in evidence array");
            }
            out.add(s);
        }
        return out;
    }

    private static Statement.Counts parseCounts(Object raw) {
        if (raw == null) {
            return new Statement.Counts(0, 0, 0, 0, 0);
        }
        Map<String, Object> obj = Json.asObject(raw, "predicate.counts");
        return new Statement.Counts(
                Json.optInt(obj, "pass", 0),
                Json.optInt(obj, "warn", 0),
                Json.optInt(obj, "fail", 0),
                Json.optInt(obj, "skip", 0),
                Json.optInt(obj, "info", 0));
    }

    private static Statement.Score parseScore(Object raw) {
        if (raw == null) {
            return null;
        }
        Map<String, Object> obj = Json.asObject(raw, "predicate.score");
        return new Statement.Score(
                Json.reqDouble(obj, "total"),
                strOrEmpty(obj, "grade"),
                Json.optInt(obj, "categoriesAssessed", 0),
                Json.optInt(obj, "categoriesTotal", 0));
    }

    private static String strOrEmpty(Map<String, Object> obj, String key) {
        String val = Json.optString(obj, key);
        return val == null ? "" : val;
    }

    private static String digestHex(String algorithm, String value) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] hash = md.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Missing JCA digest algorithm: " + algorithm, ex);
        }
    }
}

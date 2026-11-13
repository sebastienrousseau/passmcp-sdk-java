// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable representation of a verified {@code in-toto} {@code Statement/v1}
 * carrying {@code https://satellion.com/attestation/mcp-evaluation/v1}.
 */
public final class Statement {
    /** Canonical in-toto statement envelope URI. */
    public static final String STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
    /** Canonical passmcp MCP evaluation predicate URI. */
    public static final String PREDICATE_TYPE = "https://satellion.com/attestation/mcp-evaluation/v1";
    /** Canonical subjectKind value indicating target-descriptor hashing. */
    public static final String SUBJECT_KIND_DESCRIPTOR = "mcp-target-descriptor";

    /**
     * Subject descriptor entry from the in-toto statement envelope.
     *
     * @param name target endpoint name
     * @param digest algorithm-to-hex digest map
     */
    public record Subject(String name, Map<String, String> digest) {
        /** Creates an immutable defensive copy of the subject digest map. */
        public Subject {
            Objects.requireNonNull(name, "name");
            digest = digest == null ? Map.of() : Map.copyOf(digest);
        }
    }

    /**
     * Evaluated MCP server target descriptor.
     *
     * @param transport transport identifier ({@code http} or {@code stdio})
     * @param endpoint server URL or stdio command line
     */
    public record Target(String transport, String endpoint) {
    }

    /**
     * Evaluation basis recording spec revision, rubric, and check inventory versions.
     *
     * @param specRevision negotiated MCP revision (optional)
     * @param rubric rubric version (required when score is present)
     * @param checkInventory check inventory version (required)
     */
    public record Basis(String specRevision, String rubric, String checkInventory) {
    }

    /**
     * Producer instrument metadata.
     *
     * @param name tool name (for example {@code passmcp})
     * @param version tool version
     * @param reportSchemaVersion report schema version
     */
    public record Instrument(String name, String version, int reportSchemaVersion) {
    }

    /**
     * Outcome recorded for a single diagnostic check.
     *
     * @param id check identifier
     * @param phase execution phase
     * @param status check outcome ({@code pass}, {@code warn}, {@code fail}, {@code skip}, {@code info})
     * @param severity optional finding severity
     * @param evidence recorded request references
     * @param doc optional inventory documentation URL
     */
    public record Verdict(
            String id,
            String phase,
            String status,
            String severity,
            List<String> evidence,
            String doc) {
        /** Defensive copy of evidence references. */
        public Verdict {
            evidence = evidence == null ? List.of() : List.copyOf(evidence);
        }
    }

    /**
     * Tallied verdict counts across the five canonical statuses.
     *
     * @param pass passed check count
     * @param warn warning check count
     * @param fail failed check count
     * @param skip skipped check count
     * @param info informational check count
     */
    public record Counts(int pass, int warn, int fail, int skip, int info) {
    }

    /**
     * Overall evaluation score summary.
     *
     * @param total numeric score
     * @param grade letter grade
     * @param categoriesAssessed assessed category count
     * @param categoriesTotal total category count
     */
    public record Score(double total, String grade, int categoriesAssessed, int categoriesTotal) {
    }

    private final String type;
    private final List<Subject> subjects;
    private final String predicateType;
    private final String subjectKind;
    private final Target target;
    private final Basis judgedAgainst;
    private final Instrument instrument;
    private final String ranAt;
    private final String took;
    private final List<Verdict> verdicts;
    private final Counts counts;
    private final Score score;

    /**
     * Creates an evaluation statement instance.
     *
     * @param type envelope {@code _type}
     * @param subjects envelope {@code subject} list
     * @param predicateType envelope {@code predicateType}
     * @param subjectKind predicate {@code subjectKind}
     * @param target evaluated target
     * @param judgedAgainst evaluation basis
     * @param instrument producer metadata
     * @param ranAt RFC 3339 run timestamp
     * @param took run duration string
     * @param verdicts check verdicts
     * @param counts tallied status counts
     * @param score optional score summary
     */
    public Statement(
            String type,
            List<Subject> subjects,
            String predicateType,
            String subjectKind,
            Target target,
            Basis judgedAgainst,
            Instrument instrument,
            String ranAt,
            String took,
            List<Verdict> verdicts,
            Counts counts,
            Score score) {
        this.type = type;
        this.subjects = subjects == null ? List.of() : List.copyOf(subjects);
        this.predicateType = predicateType;
        this.subjectKind = subjectKind;
        this.target = target;
        this.judgedAgainst = judgedAgainst;
        this.instrument = instrument;
        this.ranAt = ranAt;
        this.took = took;
        this.verdicts = verdicts == null ? List.of() : List.copyOf(verdicts);
        this.counts = counts;
        this.score = score;
    }

    /** @return in-toto statement envelope type */
    public String type() {
        return type;
    }

    /** @return subject list */
    public List<Subject> subjects() {
        return subjects;
    }

    /** @return predicate type URI */
    public String predicateType() {
        return predicateType;
    }

    /** @return subjectKind discriminator */
    public String subjectKind() {
        return subjectKind;
    }

    /** @return evaluated target descriptor */
    public Target target() {
        return target;
    }

    /** @return evaluation basis */
    public Basis judgedAgainst() {
        return judgedAgainst;
    }

    /** @return instrument metadata */
    public Instrument instrument() {
        return instrument;
    }

    /** @return RFC 3339 timestamp when the evaluation started */
    public String ranAt() {
        return ranAt;
    }

    /** @return evaluation duration string */
    public String took() {
        return took;
    }

    /** @return recorded check verdicts */
    public List<Verdict> verdicts() {
        return verdicts;
    }

    /** @return recorded status counts */
    public Counts counts() {
        return counts;
    }

    /** @return optional score summary */
    public Optional<Score> score() {
        return Optional.ofNullable(score);
    }

    /**
     * Returns the numeric score total, or {@code null} if the statement carries no score.
     *
     * @return score total or {@code null}
     */
    public Double scoreTotal() {
        return score == null ? null : Double.valueOf(score.total());
    }

    /**
     * Returns the letter grade, or {@code null} if the statement carries no score.
     *
     * @return score grade or {@code null}
     */
    public String scoreGrade() {
        return score == null ? null : score.grade();
    }

    /**
     * Recomputes the canonical target-descriptor digests to check whether this
     * statement covers {@code (transport, endpoint)}.
     *
     * @param transport transport kind ({@code http} or {@code stdio})
     * @param endpoint server URL or command line
     * @return {@code true} when every known digest present on the single subject matches
     */
    public boolean covers(String transport, String endpoint) {
        if (subjects.size() != 1 || transport == null || endpoint == null) {
            return false;
        }
        String descriptor = AttestationVerifier.targetDescriptor(transport, endpoint);
        return AttestationVerifier.coversDescriptor(subjects.get(0).digest(), descriptor);
    }

    /**
     * Looks up the first verdict matching {@code checkId}.
     *
     * @param checkId check identifier (for example {@code protocol.origin})
     * @return matching verdict if present
     */
    public Optional<Verdict> verdictFor(String checkId) {
        if (checkId == null) {
            return Optional.empty();
        }
        for (Verdict verdict : verdicts) {
            if (checkId.equals(verdict.id())) {
                return Optional.of(verdict);
            }
        }
        return Optional.empty();
    }
}

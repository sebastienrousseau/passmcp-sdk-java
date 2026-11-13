// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SEP-2549 list response cache metadata ({@code ttlMs >= 0} and
 * {@code cacheScope} in {@code {"public", "private"}}).
 *
 * @param ttlMs cache time-to-live in milliseconds ({@code >= 0})
 * @param cacheScope cache visibility scope ({@code public} or {@code private})
 */
public record CacheHints(long ttlMs, String cacheScope) {
    /** Validates SEP-2549 invariants on construction. */
    public CacheHints {
        if (ttlMs < 0) {
            throw new IllegalArgumentException("SEP-2549 ttlMs must be >= 0, got " + ttlMs);
        }
        if (!"public".equals(cacheScope) && !"private".equals(cacheScope)) {
            throw new IllegalArgumentException(
                    "SEP-2549 cacheScope must be \"public\" or \"private\", got \"" + cacheScope + "\"");
        }
    }

    /** Creates public-scope SEP-2549 cache hints in milliseconds. */
    public static CacheHints publicScope(long ttlMs) {
        return new CacheHints(ttlMs, "public");
    }

    /** Creates private-scope SEP-2549 cache hints in milliseconds. */
    public static CacheHints privateScope(long ttlMs) {
        return new CacheHints(ttlMs, "private");
    }

    /**
     * Creates SEP-2549 cache hints from {@code (cacheable, ttlSeconds, scope)}.
     *
     * @param cacheable whether responses may be cached ({@code false} sets {@code ttlMs = 0})
     * @param ttlSeconds TTL in seconds ({@code >= 0})
     * @param scope {@code "public"} or {@code "private"}
     * @return validated {@link CacheHints}
     */
    public static CacheHints ofSeconds(boolean cacheable, long ttlSeconds, String scope) {
        if (ttlSeconds < 0) {
            throw new IllegalArgumentException("SEP-2549 ttlSeconds must be >= 0");
        }
        return new CacheHints(cacheable ? Math.multiplyExact(ttlSeconds, 1000L) : 0L, scope);
    }

    /** Validates and parses a {@code _meta} or list result map carrying {@code ttlMs} and {@code cacheScope}. */
    public static CacheHints fromMetaMap(Map<String, Object> meta) {
        if (meta == null) {
            throw new IllegalArgumentException("Missing SEP-2549 cache metadata object");
        }
        Object rawTtl = meta.get("ttlMs");
        if (!(rawTtl instanceof Long) && !(rawTtl instanceof Integer)) {
            throw new IllegalArgumentException("SEP-2549 ttlMs must be an integer");
        }
        long ttl = ((Number) rawTtl).longValue();
        String scope = Json.optString(meta, "cacheScope");
        return new CacheHints(ttl, scope);
    }

    /** Extracts SEP-2549 cache hints from top-level list result fields or {@code _meta}. */
    public static CacheHints fromResult(Map<String, Object> result) {
        if (result != null && result.containsKey("ttlMs")) {
            return fromMetaMap(result);
        }
        if (result != null && result.get("_meta") instanceof Map<?, ?> rawMeta) {
            return fromMetaMap(Json.asObject(rawMeta, "_meta"));
        }
        throw new IllegalArgumentException("Missing SEP-2549 ttlMs/cacheScope on list result");
    }

    /** Renders this hint pair as a map containing {@code ttlMs} and {@code cacheScope}. */
    public Map<String, Object> toMetaMap() {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("ttlMs", Long.valueOf(ttlMs));
        meta.put("cacheScope", cacheScope);
        return meta;
    }

    /** Attaches {@code ttlMs}, {@code cacheScope}, and {@code _meta} onto a {@code 2026-07-28} list result. */
    public void applyToListResult(Map<String, Object> out) {
        out.put("ttlMs", Long.valueOf(ttlMs));
        out.put("cacheScope", cacheScope);
        out.put("_meta", toMetaMap());
    }
}

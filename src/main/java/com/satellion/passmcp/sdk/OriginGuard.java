// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Strict HTTP {@code Origin} allowlist validator for Streamable HTTP servers.
 * Non-browser requests with no {@code Origin} header are allowed; browser requests
 * carrying {@code Origin: null}, wildcards, or unlisted origins are rejected with HTTP 403.
 */
public final class OriginGuard {
    private final Set<String> allowedOrigins;

    /**
     * Creates an {@link OriginGuard} allowing only the explicitly listed origins.
     *
     * @param origins allowed browser origins (for example {@code https://app.example.com})
     */
    public OriginGuard(Collection<String> origins) {
        Objects.requireNonNull(origins, "origins");
        Set<String> normalized = new LinkedHashSet<>();
        for (String origin : origins) {
            String clean = normalizeOrigin(origin);
            if (clean.isEmpty() || "*".equals(clean) || "null".equalsIgnoreCase(clean)) {
                throw new IllegalArgumentException("Invalid allowlist origin: \"" + origin + "\"");
            }
            normalized.add(clean);
        }
        this.allowedOrigins = Set.copyOf(normalized);
    }

    /**
     * Checks whether an incoming HTTP {@code Origin} header value is permitted.
     *
     * @param originHeader HTTP {@code Origin} header value, or {@code null} when absent
     * @return {@code true} when absent/empty (non-browser) or present in the allowlist
     */
    public boolean isAllowed(String originHeader) {
        if (originHeader == null || originHeader.isEmpty()) {
            return true;
        }
        String candidate = normalizeOrigin(originHeader);
        if (candidate.isEmpty() || "null".equalsIgnoreCase(candidate)) {
            return false;
        }
        return allowedOrigins.contains(candidate);
    }

    /**
     * Returns HTTP {@code 200} if {@code originHeader} is permitted, or {@code 403} if rejected.
     *
     * @param originHeader HTTP {@code Origin} header value, or {@code null}
     * @return {@code 200} or {@code 403}
     */
    public int statusFor(String originHeader) {
        return isAllowed(originHeader) ? 200 : 403;
    }

    private static String normalizeOrigin(String raw) {
        if (raw == null) {
            return "";
        }
        String trimmed = raw.trim();
        if (trimmed.endsWith("/")) {
            return trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }
}

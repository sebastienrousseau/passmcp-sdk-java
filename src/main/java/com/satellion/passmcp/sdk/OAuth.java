// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * OAuth 2.1 + PKCE ({@code S256}, RFC 7636), {@code WWW-Authenticate} Bearer challenge
 * builder/parser, RFC 9728 Protected Resource Metadata discovery, and RFC 8414
 * Authorization Server Metadata validation.
 */
public final class OAuth {
    private static final String BASE64URL_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private OAuth() {
    }

    /** Parsed {@code WWW-Authenticate: Bearer ...} challenge attributes. */
    public record BearerChallenge(
            String resourceMetadata, String scope, String error, String errorDescription) {
    }

    /** Validated RFC 9728 OAuth Protected Resource Metadata document. */
    public record ProtectedResourceMetadata(
            String resource, List<String> authorizationServers, List<String> scopesSupported) {
        /** Defensive list copies. */
        public ProtectedResourceMetadata {
            authorizationServers = List.copyOf(authorizationServers);
            scopesSupported = List.copyOf(scopesSupported);
        }
    }

    /** Validated RFC 8414 OAuth 2.1 Authorization Server Metadata document. */
    public record AuthorizationServerMetadata(
            String issuer,
            String authorizationEndpoint,
            String tokenEndpoint,
            String registrationEndpoint,
            List<String> codeChallengeMethodsSupported) {
        /** Defensive list copy. */
        public AuthorizationServerMetadata {
            codeChallengeMethodsSupported = List.copyOf(codeChallengeMethodsSupported);
        }
    }

    /** Generates a 64-character cryptographically random RFC 7636 PKCE verifier. */
    public static String generateVerifier() {
        return generateVerifier(64);
    }

    /** Generates an RFC 7636 PKCE verifier of {@code length} URL-safe characters ({@code 43..128}). */
    public static String generateVerifier(int length) {
        if (length < 43 || length > 128) {
            throw new IllegalArgumentException("PKCE verifier length must be in [43, 128], got " + length);
        }
        char[] out = new char[length];
        for (int i = 0; i < length; i++) {
            out[i] = BASE64URL_ALPHABET.charAt(SECURE_RANDOM.nextInt(BASE64URL_ALPHABET.length()));
        }
        return new String(out);
    }

    /** Computes {@code BASE64URL-NOPAD(SHA256(ASCII(verifier)))} per RFC 7636 section 4.2. */
    public static String computeS256Challenge(String verifier) {
        validateVerifierSyntax(verifier);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    /** Constant-time verification of a PKCE {@code verifier} against an {@code S256} {@code challenge}. */
    public static boolean verifyS256(String verifier, String challenge) {
        if (challenge == null || challenge.trim().isEmpty()) {
            return false;
        }
        String computed = computeS256Challenge(verifier);
        return MessageDigest.isEqual(
                computed.getBytes(StandardCharsets.US_ASCII),
                challenge.getBytes(StandardCharsets.US_ASCII));
    }

    /** Builds an RFC 9728 / RFC 6750 {@code WWW-Authenticate: Bearer ...} header value. */
    public static String buildBearerChallenge(
            String resourceMetadata, String scope, String error, String errorDescription) {
        List<String> parts = new ArrayList<>(4);
        appendParam(parts, "resource_metadata", resourceMetadata);
        appendParam(parts, "scope", scope);
        appendParam(parts, "error", error);
        appendParam(parts, "error_description", errorDescription);
        return parts.isEmpty() ? "Bearer" : "Bearer " + String.join(", ", parts);
    }

    /** Parses a {@code WWW-Authenticate} Bearer challenge header into structured attributes. */
    public static BearerChallenge parseBearerChallenge(String headerValue) {
        if (headerValue == null) {
            throw new IllegalArgumentException("WWW-Authenticate header must not be null");
        }
        String trimmed = headerValue.trim();
        if (trimmed.length() < 6 || !trimmed.regionMatches(true, 0, "Bearer", 0, 6)) {
            throw new IllegalArgumentException("Expected Bearer challenge in WWW-Authenticate");
        }
        String rest = trimmed.substring(6).trim();
        Map<String, String> attrs = parseAuthParams(rest);
        return new BearerChallenge(
                attrs.get("resource_metadata"),
                attrs.get("scope"),
                attrs.get("error"),
                attrs.get("error_description"));
    }

    /**
     * Derives candidate RFC 9728 section 3.1 Protected Resource Metadata well-known URLs
     * (path-suffixed first when the resource URL carries a path, followed by host root).
     */
    public static List<String> protectedResourceWellKnownUrls(String resourceUrl) {
        URI uri = requireHttpsUri(resourceUrl, "resource URL");
        String origin = uriOrigin(uri);
        String path = uri.getRawPath();
        String rootWellKnown = origin + "/.well-known/oauth-protected-resource";
        if (path == null || path.isEmpty() || "/".equals(path)) {
            return List.of(rootWellKnown);
        }
        String cleanPath = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        return List.of(rootWellKnown + cleanPath, rootWellKnown);
    }

    /** Validates an RFC 9728 Protected Resource Metadata document and enforces strict resource binding. */
    public static ProtectedResourceMetadata validateProtectedResourceMetadata(
            String rawJson, String expectedResource) {
        URI expected = requireHttpsUri(expectedResource, "expectedResource");
        Map<String, Object> doc = Json.parseObject(rawJson);
        String resource = Json.reqString(doc, "resource");
        URI actual = requireHttpsUri(resource, "metadata.resource");
        if (!normalizeResource(expected).equals(normalizeResource(actual))) {
            throw new IllegalArgumentException(
                    "RFC 9728 resource mismatch: expected " + expectedResource + ", got " + resource);
        }
        List<String> authServers = readStringArray(doc.get("authorization_servers"), "authorization_servers", true);
        for (String asUrl : authServers) {
            requireHttpsUri(asUrl, "authorization_servers entry");
        }
        List<String> scopes = doc.containsKey("scopes_supported")
                ? readStringArray(doc.get("scopes_supported"), "scopes_supported", false)
                : List.of();
        return new ProtectedResourceMetadata(resource, authServers, scopes);
    }

    /** Derives the RFC 8414 section 3 Authorization Server Metadata well-known URL for an HTTPS issuer. */
    public static String authorizationServerWellKnownUrl(String issuerUrl) {
        URI uri = requireHttpsUri(issuerUrl, "issuer URL");
        if (uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException("OAuth issuer URL must not contain query or fragment");
        }
        String origin = uriOrigin(uri);
        String path = uri.getRawPath();
        if (path == null || path.isEmpty() || "/".equals(path)) {
            return origin + "/.well-known/oauth-authorization-server";
        }
        String cleanPath = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        return origin + "/.well-known/oauth-authorization-server" + cleanPath;
    }

    /** Validates an RFC 8414 Authorization Server Metadata document for OAuth 2.1 + PKCE {@code S256}. */
    public static AuthorizationServerMetadata validateAuthorizationServerMetadata(
            String rawJson, String expectedIssuer) {
        Map<String, Object> doc = Json.parseObject(rawJson);
        String issuer = Json.reqString(doc, "issuer");
        requireHttpsUri(issuer, "issuer");
        if (expectedIssuer != null && !expectedIssuer.isEmpty() && !expectedIssuer.equals(issuer)) {
            throw new IllegalArgumentException(
                    "RFC 8414 issuer mismatch: expected " + expectedIssuer + ", got " + issuer);
        }
        String authEndpoint = Json.reqString(doc, "authorization_endpoint");
        requireHttpsUri(authEndpoint, "authorization_endpoint");
        String tokenEndpoint = Json.reqString(doc, "token_endpoint");
        requireHttpsUri(tokenEndpoint, "token_endpoint");
        String regEndpoint = Json.optString(doc, "registration_endpoint");
        if (regEndpoint != null && !regEndpoint.isEmpty()) {
            requireHttpsUri(regEndpoint, "registration_endpoint");
        }
        List<String> methods = readStringArray(
                doc.get("code_challenge_methods_supported"), "code_challenge_methods_supported", true);
        if (!methods.contains("S256")) {
            throw new IllegalArgumentException("OAuth 2.1 requires S256 in code_challenge_methods_supported");
        }
        return new AuthorizationServerMetadata(issuer, authEndpoint, tokenEndpoint, regEndpoint, methods);
    }

    private static final String PKCE_UNRESERVED =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

    private static void validateVerifierSyntax(String verifier) {
        if (verifier == null || verifier.length() < 43 || verifier.length() > 128) {
            throw new IllegalArgumentException("PKCE verifier must be 43..128 characters");
        }
        for (int i = 0; i < verifier.length(); i++) {
            if (PKCE_UNRESERVED.indexOf(verifier.charAt(i)) < 0) {
                throw new IllegalArgumentException("Invalid character in PKCE verifier");
            }
        }
    }

    private static void appendParam(List<String> out, String key, String val) {
        if (val != null && !val.isEmpty()) {
            String safe = val.replace("\\", "\\\\").replace("\"", "\\\"");
            out.add(key + "=\"" + safe + "\"");
        }
    }

    private static Map<String, String> parseAuthParams(String rest) {
        Map<String, String> map = new LinkedHashMap<>();
        int i = skipAuthDelims(rest, 0);
        while (i < rest.length()) {
            int eq = rest.indexOf('=', i);
            if (eq <= i) {
                throw new IllegalArgumentException("Malformed WWW-Authenticate parameter");
            }
            String key = rest.substring(i, eq).trim().toLowerCase(Locale.ROOT);
            i = skipSpaces(rest, eq + 1);
            i = readParamValue(rest, i, map, key);
            i = skipAuthDelims(rest, i);
        }
        return map;
    }

    private static int skipAuthDelims(String src, int pos) {
        int i = pos;
        while (i < src.length() && (Character.isWhitespace(src.charAt(i)) || src.charAt(i) == ',')) {
            i++;
        }
        return i;
    }

    private static int skipSpaces(String src, int pos) {
        int i = pos;
        while (i < src.length() && Character.isWhitespace(src.charAt(i))) {
            i++;
        }
        return i;
    }

    private static int readParamValue(String rest, int pos, Map<String, String> map, String key) {
        if (pos < rest.length() && rest.charAt(pos) == '"') {
            return readQuotedParam(rest, pos + 1, map, key)[0];
        }
        int end = pos;
        while (end < rest.length() && rest.charAt(end) != ',' && !Character.isWhitespace(rest.charAt(end))) {
            end++;
        }
        map.put(key, rest.substring(pos, end));
        return end;
    }

    private static int[] readQuotedParam(String src, int pos, Map<String, String> out, String key) {
        StringBuilder sb = new StringBuilder();
        int i = pos;
        while (i < src.length()) {
            char c = src.charAt(i++);
            if (c == '\\' && i < src.length()) {
                sb.append(src.charAt(i++));
            } else if (c == '"') {
                out.put(key, sb.toString());
                return new int[]{i};
            } else {
                sb.append(c);
            }
        }
        throw new IllegalArgumentException("Unterminated quoted string in WWW-Authenticate");
    }

    private static URI requireHttpsUri(String raw, String label) {
        if (raw == null || raw.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing " + label);
        }
        URI uri = URI.create(raw.trim());
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getHost().isEmpty()) {
            throw new IllegalArgumentException(label + " must use https with a non-empty host: " + raw);
        }
        return uri;
    }

    private static String uriOrigin(URI uri) {
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        int port = uri.getPort();
        return (port == -1 || port == 443) ? "https://" + host : "https://" + host + ":" + port;
    }

    private static String normalizeResource(URI uri) {
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) path = "";
        else if (path.length() > 1 && path.endsWith("/")) path = path.substring(0, path.length() - 1);
        return uriOrigin(uri) + path;
    }

    private static List<String> readStringArray(Object raw, String field, boolean nonEmpty) {
        List<Object> arr = Json.asArray(raw, field);
        if (nonEmpty && arr.isEmpty()) {
            throw new IllegalArgumentException(field + " must not be empty");
        }
        List<String> out = new ArrayList<>(arr.size());
        for (Object item : arr) {
            if (!(item instanceof String s) || s.trim().isEmpty()) {
                throw new IllegalArgumentException(field + " must contain non-empty strings");
            }
            out.add(s);
        }
        return out;
    }
}

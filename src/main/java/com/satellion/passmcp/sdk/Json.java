// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bounds-checked RFC 8259 JSON parser and serializer with zero external dependencies.
 */
public final class Json {
    private static final int MAX_DEPTH = 64;

    private Json() {
    }

    /** Parses an RFC 8259 JSON text into standard Java collections and primitives. */
    public static Object parse(String input) {
        if (input == null) {
            throw new IllegalArgumentException("JSON input must not be null");
        }
        Cursor cur = new Cursor(input);
        cur.skipWs();
        Object value = cur.readValue(0);
        cur.skipWs();
        if (!cur.eof()) {
            throw cur.fail("Unexpected trailing content");
        }
        return value;
    }

    /** Parses a JSON object text and returns a string-keyed map. */
    public static Map<String, Object> parseObject(String input) {
        return asObject(parse(input), "root");
    }

    /** Serializes a Java value into compact RFC 8259 JSON. */
    public static String stringify(Object value) {
        StringBuilder sb = new StringBuilder(128);
        writeValue(sb, value, 0);
        return sb.toString();
    }

    /** Converts an untrusted object value into a typed {@code Map<String, Object>}. */
    public static Map<String, Object> asObject(Object value, String field) {
        if (!(value instanceof Map<?, ?> raw)) {
            throw new IllegalArgumentException("Expected JSON object for " + field);
        }
        Map<String, Object> out = new LinkedHashMap<>(raw.size());
        for (Map.Entry<?, ?> entry : raw.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IllegalArgumentException("Non-string key in " + field);
            }
            out.put(key, entry.getValue());
        }
        return out;
    }

    /** Converts an untrusted list value into a {@code List<Object>}. */
    public static List<Object> asArray(Object value, String field) {
        if (!(value instanceof List<?> raw)) {
            throw new IllegalArgumentException("Expected JSON array for " + field);
        }
        return new ArrayList<>(raw);
    }

    /** Reads an optional string property, returning {@code null} when absent or JSON null. */
    public static String optString(Map<String, Object> obj, String key) {
        Object val = obj.get(key);
        if (val == null) {
            return null;
        }
        if (val instanceof String s) {
            return s;
        }
        throw new IllegalArgumentException("Expected string for " + key);
    }

    /** Reads a required string property. */
    public static String reqString(Map<String, Object> obj, String key) {
        String val = optString(obj, key);
        if (val == null) {
            throw new IllegalArgumentException("Missing string field " + key);
        }
        return val;
    }

    /** Reads an integer property, defaulting to {@code fallback} when absent. */
    public static int optInt(Map<String, Object> obj, String key, int fallback) {
        Object val = obj.get(key);
        if (val == null) {
            return fallback;
        }
        if (val instanceof Long l && l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE) {
            return l.intValue();
        }
        if (val instanceof Integer i) {
            return i;
        }
        throw new IllegalArgumentException("Expected integer for " + key);
    }

    /** Reads a required exact integer property. */
    public static int reqInt(Map<String, Object> obj, String key) {
        if (!obj.containsKey(key) || obj.get(key) == null) {
            throw new IllegalArgumentException("Missing integer field " + key);
        }
        return optInt(obj, key, 0);
    }

    /** Reads a numeric property as a {@code double}. */
    public static double reqDouble(Map<String, Object> obj, String key) {
        Object val = obj.get(key);
        if (val instanceof Number n) {
            return n.doubleValue();
        }
        throw new IllegalArgumentException("Expected number for " + key);
    }

    private static void writeValue(StringBuilder sb, Object value, int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("JSON nesting exceeds maximum depth");
        }
        if (value instanceof Collection<?> list) {
            writeArray(sb, list, depth + 1);
        } else if (value instanceof Map<?, ?> map) {
            writeObject(sb, map, depth + 1);
        } else {
            writeScalar(sb, value);
        }
    }

    private static void writeScalar(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof Boolean b) {
            sb.append(b.booleanValue());
        } else if (value instanceof Number n) {
            writeNumber(sb, n);
        } else if (value instanceof String s) {
            writeString(sb, s);
        } else {
            throw new IllegalArgumentException("Unsupported JSON value type: " + value.getClass().getName());
        }
    }

    private static void writeNumber(StringBuilder sb, Number n) {
        double d = n.doubleValue();
        if (Double.isNaN(d) || Double.isInfinite(d)) {
            throw new IllegalArgumentException("Non-finite numbers are not valid JSON");
        }
        sb.append(n);
    }

    private static void writeArray(StringBuilder sb, Collection<?> items, int depth) {
        sb.append('[');
        boolean first = true;
        for (Object item : items) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            writeValue(sb, item, depth);
        }
        sb.append(']');
    }

    private static void writeObject(StringBuilder sb, Map<?, ?> map, int depth) {
        sb.append('{');
        boolean first = true;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IllegalArgumentException("JSON object keys must be strings");
            }
            if (!first) {
                sb.append(',');
            }
            first = false;
            writeString(sb, key);
            sb.append(':');
            writeValue(sb, entry.getValue(), depth);
        }
        sb.append('}');
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            appendEscapedChar(sb, s.charAt(i));
        }
        sb.append('"');
    }

    private static void appendEscapedChar(StringBuilder sb, char c) {
        switch (c) {
            case '"' -> sb.append("\\\"");
            case '\\' -> sb.append("\\\\");
            case '\b' -> sb.append("\\b");
            case '\f' -> sb.append("\\f");
            case '\n' -> sb.append("\\n");
            case '\r' -> sb.append("\\r");
            case '\t' -> sb.append("\\t");
            default -> sb.append(c < 0x20 ? String.format("\\u%04x", (int) c) : String.valueOf(c));
        }
    }

    private static final class Cursor {
        private final String src;
        private int pos;

        Cursor(String src) {
            this.src = src;
        }

        boolean eof() {
            return pos >= src.length();
        }

        char peek() {
            if (eof()) {
                throw fail("Unexpected end of input");
            }
            return src.charAt(pos);
        }

        void skipWs() {
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                    break;
                }
                pos++;
            }
        }

        IllegalArgumentException fail(String msg) {
            return new IllegalArgumentException(msg + " at offset " + pos);
        }

        Object readValue(int depth) {
            if (depth > MAX_DEPTH) {
                throw fail("Maximum nesting depth exceeded");
            }
            skipWs();
            return switch (peek()) {
                case '{' -> readObject(depth + 1);
                case '[' -> readArray(depth + 1);
                case '"' -> readString();
                case 't' -> readLiteral("true", Boolean.TRUE);
                case 'f' -> readLiteral("false", Boolean.FALSE);
                case 'n' -> readLiteral("null", null);
                default -> readNumber();
            };
        }

        Map<String, Object> readObject(int depth) {
            pos++;
            skipWs();
            Map<String, Object> map = new LinkedHashMap<>();
            if (peek() == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWs();
                if (peek() != '"') {
                    throw fail("Expected string key");
                }
                String key = readString();
                skipWs();
                expect(':');
                map.put(key, readValue(depth));
                skipWs();
                char sep = peek();
                pos++;
                if (sep == '}') {
                    return map;
                }
                if (sep != ',') {
                    throw fail("Expected ',' or '}'");
                }
            }
        }

        List<Object> readArray(int depth) {
            pos++;
            skipWs();
            List<Object> list = new ArrayList<>();
            if (peek() == ']') {
                pos++;
                return list;
            }
            while (true) {
                list.add(readValue(depth));
                skipWs();
                char sep = peek();
                pos++;
                if (sep == ']') {
                    return list;
                }
                if (sep != ',') {
                    throw fail("Expected ',' or ']'");
                }
            }
        }

        String readString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = peek();
                pos++;
                if (c == '"') {
                    return sb.toString();
                }
                if (c < 0x20) {
                    throw fail("Unescaped control character in string");
                }
                sb.append(c == '\\' ? readEscape() : c);
            }
        }

        char readEscape() {
            char esc = peek();
            pos++;
            return switch (esc) {
                case '"', '\\', '/' -> esc;
                case 'b' -> '\b';
                case 'f' -> '\f';
                case 'n' -> '\n';
                case 'r' -> '\r';
                case 't' -> '\t';
                case 'u' -> readHexQuad();
                default -> throw fail("Invalid escape sequence");
            };
        }

        char readHexQuad() {
            if (pos + 4 > src.length()) {
                throw fail("Truncated unicode escape");
            }
            int code = 0;
            for (int i = 0; i < 4; i++) {
                int digit = Character.digit(src.charAt(pos++), 16);
                if (digit < 0) {
                    throw fail("Invalid hex digit in unicode escape");
                }
                code = (code << 4) | digit;
            }
            return (char) code;
        }

        Object readLiteral(String word, Object result) {
            if (!src.startsWith(word, pos)) {
                throw fail("Invalid literal");
            }
            pos += word.length();
            return result;
        }

        Number readNumber() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            readIntegerDigits();
            boolean floating = scanFractionAndExponent();
            return parseNumericToken(src.substring(start, pos), floating);
        }

        void readIntegerDigits() {
            char first = peek();
            if (first == '0') {
                pos++;
                if (!eof() && isDigit(src.charAt(pos))) {
                    throw fail("Leading zero is not allowed");
                }
                return;
            }
            if (!isDigit(first)) {
                throw fail("Invalid number");
            }
            consumeDigits();
        }

        boolean scanFractionAndExponent() {
            boolean floating = false;
            if (!eof() && src.charAt(pos) == '.') {
                floating = true;
                pos++;
                requireDigitAndConsume();
            }
            if (!eof() && (src.charAt(pos) == 'e' || src.charAt(pos) == 'E')) {
                floating = true;
                pos++;
                if (!eof() && (src.charAt(pos) == '+' || src.charAt(pos) == '-')) {
                    pos++;
                }
                requireDigitAndConsume();
            }
            return floating;
        }

        void requireDigitAndConsume() {
            if (eof() || !isDigit(src.charAt(pos))) {
                throw fail("Expected digit in number");
            }
            consumeDigits();
        }

        void consumeDigits() {
            while (!eof() && isDigit(src.charAt(pos))) {
                pos++;
            }
        }

        Number parseNumericToken(String token, boolean floating) {
            if (!floating) {
                try {
                    return Long.valueOf(token);
                } catch (NumberFormatException ignored) {
                    // Fall through to double representation for large integers.
                }
            }
            double d = Double.parseDouble(token);
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw fail("Numeric overflow");
            }
            return Double.valueOf(d);
        }

        void expect(char expected) {
            if (peek() != expected) {
                throw fail("Expected '" + expected + "'");
            }
            pos++;
        }

        static boolean isDigit(char c) {
            return c >= '0' && c <= '9';
        }
    }
}

package cloud.smarttasks.smartgate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** A small JSON reader (objects: LinkedHashMap, arrays: ArrayList, integers: Long, others: Double)
 *  and the canonical writer of spec/SEMANTICS.md. No dependencies. */
public final class Json {
    private final String s;
    private int i;

    private Json(String s) { this.s = s; }

    public static Object parse(String text) {
        Json p = new Json(text);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != p.s.length()) throw new IllegalArgumentException("trailing data at " + p.i);
        return v;
    }

    private void ws() { while (i < s.length() && " \n\r\t".indexOf(s.charAt(i)) >= 0) i++; }

    private Object value() {
        if (i >= s.length()) throw new IllegalArgumentException("unexpected end");
        char c = s.charAt(i);
        if (c == 'n') return lit("null", null);
        if (c == 't') return lit("true", Boolean.TRUE);
        if (c == 'f') return lit("false", Boolean.FALSE);
        if (c == '"') return string();
        if (c == '[') {
            i++;
            List<Object> out = new ArrayList<>();
            ws();
            if (s.charAt(i) == ']') { i++; return out; }
            while (true) {
                ws(); out.add(value()); ws();
                char d = s.charAt(i++);
                if (d == ']') return out;
                if (d != ',') throw new IllegalArgumentException("bad array");
            }
        }
        if (c == '{') {
            i++;
            Map<String, Object> out = new LinkedHashMap<>();
            ws();
            if (s.charAt(i) == '}') { i++; return out; }
            while (true) {
                ws();
                String k = string();
                ws();
                if (s.charAt(i++) != ':') throw new IllegalArgumentException("expected :");
                ws();
                out.put(k, value());
                ws();
                char d = s.charAt(i++);
                if (d == '}') return out;
                if (d != ',') throw new IllegalArgumentException("bad object");
            }
        }
        return number();
    }

    private Object lit(String w, Object v) {
        if (!s.startsWith(w, i)) throw new IllegalArgumentException("bad literal at " + i);
        i += w.length();
        return v;
    }

    private Object number() {
        int st = i;
        while (i < s.length() && "+-.eE0123456789".indexOf(s.charAt(i)) >= 0) i++;
        String t = s.substring(st, i);
        if (t.isEmpty()) throw new IllegalArgumentException("unexpected character at " + st);
        if (t.indexOf('.') < 0 && t.indexOf('e') < 0 && t.indexOf('E') < 0) {
            try { return Long.parseLong(t); } catch (NumberFormatException e) { /* fall through */ }
        }
        return Double.parseDouble(t);
    }

    private String string() {
        if (s.charAt(i) != '"') throw new IllegalArgumentException("expected string");
        i++;
        StringBuilder b = new StringBuilder();
        while (true) {
            char c = s.charAt(i++);
            if (c == '"') return b.toString();
            if (c != '\\') { b.append(c); continue; }
            char e = s.charAt(i++);
            switch (e) {
                case '"': b.append('"'); break;
                case '\\': b.append('\\'); break;
                case '/': b.append('/'); break;
                case 'b': b.append('\b'); break;
                case 'f': b.append('\f'); break;
                case 'n': b.append('\n'); break;
                case 'r': b.append('\r'); break;
                case 't': b.append('\t'); break;
                case 'u': b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; break;
                default: throw new IllegalArgumentException("bad escape");
            }
        }
    }

    private static void str(StringBuilder b, String x) {
        b.append('"');
        for (int k = 0; k < x.length(); k++) {
            char c = x.charAt(k);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
            }
        }
        b.append('"');
    }

    /** Canonical JSON; throws for floating-point numbers and non-ASCII keys. */
    public static String canonical(Object v) {
        StringBuilder b = new StringBuilder();
        canon(b, v);
        return b.toString();
    }

    @SuppressWarnings("unchecked")
    private static void canon(StringBuilder b, Object v) {
        if (v == null) b.append("null");
        else if (v instanceof Boolean) b.append(((Boolean) v) ? "true" : "false");
        else if (v instanceof Long || v instanceof Integer) b.append(v.toString());
        else if (v instanceof Number) throw new IllegalArgumentException("canonical JSON allows integers only");
        else if (v instanceof String) str(b, (String) v);
        else if (v instanceof List) {
            b.append('[');
            boolean first = true;
            for (Object x : (List<Object>) v) { if (!first) b.append(','); first = false; canon(b, x); }
            b.append(']');
        } else if (v instanceof Map) {
            TreeMap<String, Object> m = new TreeMap<>((Map<String, Object>) v);
            b.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : m.entrySet()) {
                for (char c : e.getKey().toCharArray()) if (c > 0x7f) throw new IllegalArgumentException("keys must be ASCII");
                if (!first) b.append(',');
                first = false;
                str(b, e.getKey());
                b.append(':');
                canon(b, e.getValue());
            }
            b.append('}');
        } else throw new IllegalArgumentException("cannot encode " + v.getClass());
    }

    /** Plain JSON (floats allowed) for requests. */
    @SuppressWarnings("unchecked")
    public static String write(Object v) {
        if (v instanceof Double || v instanceof Float) return v.toString();
        if (v instanceof List) {
            StringBuilder b = new StringBuilder("[");
            for (Object x : (List<Object>) v) { if (b.length() > 1) b.append(','); b.append(write(x)); }
            return b.append(']').toString();
        }
        if (v instanceof Map) {
            StringBuilder b = new StringBuilder("{");
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                if (b.length() > 1) b.append(',');
                str(b, e.getKey());
                b.append(':').append(write(e.getValue()));
            }
            return b.append('}').toString();
        }
        return canonical(v);
    }
}

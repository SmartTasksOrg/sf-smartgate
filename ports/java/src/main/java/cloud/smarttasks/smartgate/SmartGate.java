package cloud.smarttasks.smartgate;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** SmartGate for Java: policy, decision engine, kill registry, session and audit chain
 *  (spec/SEMANTICS.md). Tested by the shared vectors in spec/conformance. */
public final class SmartGate {
    private SmartGate() {}

    public static final List<String> FRICTIONS = List.of("allow", "prompt", "block");

    static String stronger(String a, String b) { return FRICTIONS.indexOf(a) >= FRICTIONS.indexOf(b) ? a : b; }

    public static class PolicyError extends RuntimeException { PolicyError(String m) { super(m); } }
    public static class ActionError extends RuntimeException { ActionError(String m) { super(m); } }
    public static class Killed extends RuntimeException {
        public final String actionId, reason;
        Killed(String id, String reason) { super("SmartGate killed action " + id + ": " + reason); actionId = id; this.reason = reason; }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object v, String err, java.util.function.Function<String, RuntimeException> mk) {
        if (!(v instanceof Map)) throw mk.apply(err);
        return (Map<String, Object>) v;
    }

    static long intIn(Map<String, Object> m, String k, boolean present, String what, long lo, long hi) {
        Object v = m.get(k);
        if (!(v instanceof Long)) throw new PolicyError(what + " must be an integer");
        long x = (Long) v;
        if (x < lo || x > hi) throw new PolicyError(what + " must be between " + lo + " and " + hi);
        return x;
    }

    static String friction(Object v, String what) {
        if (!(v instanceof String) || !FRICTIONS.contains(v)) throw new PolicyError(what + " must be one of allow, prompt, block");
        return (String) v;
    }

    public static final class Level {
        public final String name, friction; public final long maxScore;
        Level(String n, long m, String f) { name = n; maxScore = m; friction = f; }
    }

    public static final class Policy {
        public final List<Double> bandMax = new ArrayList<>();   // null = open
        public final List<Long> bandScore = new ArrayList<>();
        public final Map<String, Long> floors = new HashMap<>();
        public long defaultFloor, irreversibleBonus;
        public final List<Level> levels = new ArrayList<>();
        public long[] cascade;            // window_ms, max_actions, max_cumulative_risk
        public String cascadeEscalate;
        public Long lowBelow;
        public String lowEscalate;
        public long approvalTimeoutMs = 300000;
        public String fallback = "allow";

        public static Policy defaults() {
            try (InputStream in = SmartGate.class.getResourceAsStream("policy.default.json")) {
                return parse(Json.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8)));
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        /** Validate and read a decoded policy (spec/conformance/policies.json). */
        @SuppressWarnings("unchecked")
        public static Policy parse(Object docV) {
            Map<String, Object> doc = obj(docV, "policy must be a JSON object", PolicyError::new);
            if (!"smartgate.policy/v1".equals(doc.get("schema"))) throw new PolicyError("schema must be \"smartgate.policy/v1\"");
            Policy p = new Policy();
            Object bv = doc.get("cost_bands");
            if (!(bv instanceof List) || ((List<Object>) bv).isEmpty()) throw new PolicyError("cost_bands must be a non-empty list");
            List<Object> bands = (List<Object>) bv;
            Double last = null;
            for (int i = 0; i < bands.size(); i++) {
                Map<String, Object> b = obj(bands.get(i), "cost_bands[" + i + "] must be an object", PolicyError::new);
                long sc = intIn(b, "score", true, "cost_bands[" + i + "].score", 0, 10);
                Object m = b.get("max_usd");
                if (m == null) {
                    if (i != bands.size() - 1) throw new PolicyError("only the last band may have max_usd null");
                    p.bandMax.add(null);
                } else {
                    if (!(m instanceof Number)) throw new PolicyError("cost_bands[" + i + "].max_usd must be a number");
                    double f = ((Number) m).doubleValue();
                    if (last != null && f <= last) throw new PolicyError("cost_bands max_usd must increase");
                    last = f;
                    p.bandMax.add(f);
                }
                p.bandScore.add(sc);
            }
            if (p.bandMax.get(p.bandMax.size() - 1) != null) throw new PolicyError("the last band must have max_usd null");
            if (doc.containsKey("action_floors")) {
                Map<String, Object> fl = obj(doc.get("action_floors"), "action_floors must be an object", PolicyError::new);
                for (String k : fl.keySet()) p.floors.put(k, intIn(fl, k, true, "action_floors." + k, 0, 10));
            }
            if (doc.containsKey("default_floor")) p.defaultFloor = intIn(doc, "default_floor", true, "default_floor", 0, 10);
            if (doc.containsKey("irreversible_bonus")) p.irreversibleBonus = intIn(doc, "irreversible_bonus", true, "irreversible_bonus", 0, 10);
            Object lv = doc.get("levels");
            if (!(lv instanceof List) || ((List<Object>) lv).isEmpty()) throw new PolicyError("levels must be a non-empty list");
            long prev = -1;
            Set<String> names = new HashSet<>();
            int i = 0;
            for (Object o : (List<Object>) lv) {
                if (!(o instanceof Map) || !(((Map<String, Object>) o).get("name") instanceof String) || ((String) ((Map<String, Object>) o).get("name")).isEmpty())
                    throw new PolicyError("levels[" + i + "] needs a name");
                Map<String, Object> l = (Map<String, Object>) o;
                String name = (String) l.get("name");
                if (!names.add(name)) throw new PolicyError("level name " + name + " repeated");
                long ms = intIn(l, "max_score", true, "levels[" + i + "].max_score", 0, 10);
                if (ms <= prev) throw new PolicyError("levels max_score must increase");
                prev = ms;
                p.levels.add(new Level(name, ms, friction(l.get("friction"), "levels[" + i + "].friction")));
                i++;
            }
            if (prev != 10) throw new PolicyError("the last level must have max_score 10");
            if (doc.get("cascade") != null) {
                Map<String, Object> c = obj(doc.get("cascade"), "cascade must be an object or null", PolicyError::new);
                p.cascade = new long[] {
                    intIn(c, "window_ms", true, "cascade.window_ms", 1, Long.MAX_VALUE),
                    intIn(c, "max_actions", true, "cascade.max_actions", 1, Long.MAX_VALUE),
                    intIn(c, "max_cumulative_risk", true, "cascade.max_cumulative_risk", 0, Long.MAX_VALUE)};
                p.cascadeEscalate = friction(c.get("escalate_to"), "cascade.escalate_to");
            }
            if (doc.get("low_confidence") != null) {
                Map<String, Object> c = obj(doc.get("low_confidence"), "low_confidence must be an object or null", PolicyError::new);
                p.lowBelow = intIn(c, "below_permille", true, "low_confidence.below_permille", 0, 1000);
                p.lowEscalate = friction(c.get("escalate_to"), "low_confidence.escalate_to");
            }
            if (doc.containsKey("approval")) {
                Map<String, Object> a = obj(doc.get("approval"), "approval must be an object", PolicyError::new);
                if (a.containsKey("timeout_ms")) p.approvalTimeoutMs = intIn(a, "timeout_ms", true, "approval.timeout_ms", 1, Long.MAX_VALUE);
                if (a.containsKey("on_timeout") && !List.of("reject", "approve").contains(a.get("on_timeout")))
                    throw new PolicyError("approval.on_timeout must be reject or approve");
            }
            if (doc.containsKey("fallback")) {
                Object f = doc.get("fallback");
                if (!List.of("allow", "block", "block_high").contains(f)) throw new PolicyError("fallback must be allow, block or block_high");
                p.fallback = (String) f;
            }
            return p;
        }
    }

    public static final class Action {
        public String actionId, agentId, actionType;
        public double costUsd;
        public boolean reversible = true;
        public Long confidence;
        public long tsMs;

        public static Action parse(Object v) {
            Map<String, Object> m = obj(v, "action must be an object", ActionError::new);
            Action a = new Action();
            String[] keys = {"action_id", "agent_id", "action_type"};
            String[] vals = new String[3];
            for (int i = 0; i < 3; i++) {
                Object x = m.get(keys[i]);
                if (!(x instanceof String) || ((String) x).isEmpty()) throw new ActionError("action." + keys[i] + " must be a non-empty string");
                vals[i] = (String) x;
            }
            a.actionId = vals[0]; a.agentId = vals[1]; a.actionType = vals[2];
            if (m.containsKey("cost_usd")) {
                Object c = m.get("cost_usd");
                if (!(c instanceof Number) || ((Number) c).doubleValue() < 0) throw new ActionError("action.cost_usd must be a number >= 0");
                a.costUsd = ((Number) c).doubleValue();
            }
            if (m.containsKey("reversible")) {
                if (!(m.get("reversible") instanceof Boolean)) throw new ActionError("action.reversible must be true or false");
                a.reversible = (Boolean) m.get("reversible");
            }
            if (m.get("confidence_permille") != null) {
                Object c = m.get("confidence_permille");
                if (!(c instanceof Long) || (Long) c < 0 || (Long) c > 1000) throw new ActionError("action.confidence_permille must be an integer 0-1000");
                a.confidence = (Long) c;
            }
            if (m.containsKey("ts_ms")) {
                Object t = m.get("ts_ms");
                if (!(t instanceof Long) || (Long) t < 0) throw new ActionError("action.ts_ms must be an integer >= 0");
                a.tsMs = (Long) t;
            }
            if (m.get("target") != null && !(m.get("target") instanceof String)) throw new ActionError("action.target must be a string");
            return a;
        }
    }

    public static long score(Policy p, Action a) {
        long s = p.bandScore.get(p.bandScore.size() - 1);
        for (int i = 0; i < p.bandMax.size(); i++) {
            Double m = p.bandMax.get(i);
            if (m == null || a.costUsd <= m) { s = p.bandScore.get(i); break; }
        }
        s = Math.max(s, p.floors.getOrDefault(a.actionType, p.defaultFloor));
        if (!a.reversible) s += p.irreversibleBonus;
        return Math.max(0, Math.min(10, s));
    }

    public static Level levelOf(Policy p, long s) {
        for (Level l : p.levels) if (s <= l.maxScore) return l;
        return p.levels.get(p.levels.size() - 1);
    }

    public static final class Engine {
        public final Policy policy;
        private final Map<String, List<long[]>> hist = new HashMap<>();
        public Engine(Policy p) { policy = p == null ? Policy.defaults() : p; }

        public synchronized Map<String, Object> decide(Action a, boolean halted, boolean killed) {
            long s = score(policy, a);
            Level lv = levelOf(policy, s);
            String fr = lv.friction;
            List<Object> reasons = new ArrayList<>();
            reasons.add("GATE-LEVEL-" + lv.name.toUpperCase(Locale.ROOT));
            if (!policy.floors.containsKey(a.actionType)) reasons.add("GATE-UNLISTED-TYPE");
            boolean cascade = false;
            if (policy.cascade != null) {
                List<long[]> h = new ArrayList<>();
                for (long[] e : hist.getOrDefault(a.agentId, List.of())) if (e[0] >= a.tsMs - policy.cascade[0]) h.add(e);
                h.add(new long[] {a.tsMs, s});
                hist.put(a.agentId, h);
                long sum = 0;
                for (long[] e : h) sum += e[1];
                cascade = h.size() > policy.cascade[1] && sum > policy.cascade[2];
                if (cascade) { fr = stronger(fr, policy.cascadeEscalate); reasons.add("GATE-CASCADE"); }
            }
            if (policy.lowBelow != null && a.confidence != null && a.confidence < policy.lowBelow) {
                fr = stronger(fr, policy.lowEscalate);
                reasons.add("GATE-LOW-CONFIDENCE");
            }
            if (halted) { fr = "block"; reasons.add("GATE-AGENT-HALTED"); }
            if (killed) { fr = "block"; reasons.add("GATE-KILLED"); }
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("action_id", a.actionId); d.put("agent_id", a.agentId); d.put("decision", fr);
            d.put("score", s); d.put("level", lv.name); d.put("reasons", reasons); d.put("cascade", cascade);
            return d;
        }
    }

    public static final class Registry {
        private final Map<String, String[]> actions = new HashMap<>();   // agent (nullable), state, reason
        private final Map<String, Boolean> halted = new HashMap<>();
        private final Map<String, TreeSet<String>> byAgent = new HashMap<>();

        private static Map<String, Object> m(Object... kv) {
            Map<String, Object> r = new LinkedHashMap<>();
            for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
            return r;
        }

        public synchronized boolean isHalted(String agent) { return halted.getOrDefault(agent, false); }

        public synchronized String register(String id, String agent) {
            String[] cur = actions.get(id);
            if (cur != null) {
                if (cur[0] == null) { cur[0] = agent; byAgent.computeIfAbsent(agent, k -> new TreeSet<>()).add(id); }
                return cur[1];
            }
            boolean h = isHalted(agent);
            actions.put(id, new String[] {agent, h ? "killed" : "pending", h ? "agent_halted" : ""});
            byAgent.computeIfAbsent(agent, k -> new TreeSet<>()).add(id);
            return h ? "killed" : "pending";
        }

        public synchronized boolean start(String id) {
            String[] cur = actions.get(id);
            if (cur == null || cur[1].equals("killed") || cur[1].equals("completed")) return false;
            cur[1] = "running";
            return true;
        }

        public synchronized String complete(String id) {
            String[] cur = actions.get(id);
            if (cur == null) return "unknown";
            if (cur[1].equals("pending") || cur[1].equals("running")) cur[1] = "completed";
            return cur[1];
        }

        public synchronized Map<String, Object> kill(String id, String reason) {
            String[] cur = actions.get(id);
            if (cur == null) {
                actions.put(id, new String[] {null, "killed", reason});
                return m("action_id", id, "status", "killed", "first", true);
            }
            if (cur[1].equals("completed")) return m("action_id", id, "status", "completed", "first", false, "warning", "already_completed");
            if (cur[1].equals("killed")) return m("action_id", id, "status", "killed", "first", false);
            cur[1] = "killed";
            cur[2] = reason;
            return m("action_id", id, "status", "killed", "first", true);
        }

        public synchronized Map<String, Object> killAgent(String agent, String reason) {
            boolean first = !isHalted(agent);
            halted.put(agent, true);
            List<Object> killed = new ArrayList<>();
            for (String id : new ArrayList<>(byAgent.getOrDefault(agent, new TreeSet<>()))) {
                Map<String, Object> r = kill(id, reason.isEmpty() ? "agent_halted" : reason);
                if ("killed".equals(r.get("status")) && Boolean.TRUE.equals(r.get("first"))) killed.add(id);
            }
            return m("agent_id", agent, "status", "halted", "first", first, "killed", killed);
        }

        public synchronized Map<String, Object> releaseAgent(String agent) {
            boolean first = isHalted(agent);
            halted.put(agent, false);
            return m("agent_id", agent, "status", "released", "first", first);
        }

        public synchronized void checkpoint(String id) {
            String[] cur = actions.get(id);
            if (cur != null && cur[1].equals("killed")) throw new Killed(id, cur[2]);
        }
    }

    /** The deterministic core the sequence vectors run. */
    public static final class Session {
        public final Engine engine;
        public final Registry registry = new Registry();
        public Session(Policy p) { engine = new Engine(p); }

        @SuppressWarnings("unchecked")
        public Object apply(Map<String, Object> step) {
            String op = (String) step.get("op");
            String id = (String) step.get("action_id");
            String reason = step.get("reason") == null ? "" : (String) step.get("reason");
            switch (op) {
                case "evaluate": {
                    Action a = Action.parse(step.get("action"));
                    String st = registry.register(a.actionId, a.agentId);
                    return engine.decide(a, registry.isHalted(a.agentId), st.equals("killed"));
                }
                case "kill": return registry.kill(id, reason);
                case "kill_agent": return registry.killAgent((String) step.get("agent_id"), reason);
                case "release_agent": return registry.releaseAgent((String) step.get("agent_id"));
                case "start": return Registry.m("action_id", id, "started", registry.start(id));
                case "complete": return Registry.m("action_id", id, "state", registry.complete(id));
                default: throw new IllegalArgumentException("unknown op " + op);
            }
        }
    }

    public static final String GENESIS = "0".repeat(64);

    public static String sha256(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder b = new StringBuilder();
            for (byte x : d) b.append(String.format("%02x", x));
            return b.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String recordHash(Map<String, Object> rec) {
        Map<String, Object> body = new HashMap<>(rec);
        body.remove("hash");
        return sha256(Json.canonical(body));
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> chain(List<Object> events) {
        String prev = GENESIS;
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < events.size(); i++) {
            Map<String, Object> e = (Map<String, Object>) events.get(i);
            Map<String, Object> rec = new HashMap<>();
            if (e.get("fields") instanceof Map) rec.putAll((Map<String, Object>) e.get("fields"));
            rec.put("seq", (long) i); rec.put("ts_ms", e.get("ts_ms")); rec.put("event", e.get("event")); rec.put("prev", prev);
            String h = recordHash(rec);
            rec.put("hash", h);
            prev = h;
            out.add(rec);
        }
        return out;
    }

    /** Index of the first bad record, or -1. */
    public static int verify(List<Map<String, Object>> records) {
        String prev = GENESIS;
        for (int i = 0; i < records.size(); i++) {
            Map<String, Object> r = records.get(i);
            if (!Long.valueOf(i).equals(r.get("seq"))) return i;
            if (!prev.equals(r.get("prev"))) return i;
            String h;
            try { h = recordHash(r); } catch (RuntimeException e) { return i; }
            if (!h.equals(r.get("hash"))) return i;
            prev = h;
        }
        return -1;
    }
}

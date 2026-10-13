package cloud.smarttasks.smartgate;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Runs spec/conformance against the Java port. Usage: java ... Conformance [dir] */
public final class Conformance {
    @SuppressWarnings("unchecked")
    static Map<String, Object> load(String dir, String n) throws Exception {
        return (Map<String, Object>) Json.parse(Files.readString(Path.of(dir, n)));
    }

    static SmartGate.Policy policy(Object p) {
        return p == null || "default".equals(p) ? SmartGate.Policy.defaults() : SmartGate.Policy.parse(p);
    }

    static String c(Object v) {
        try { return Json.canonical(v); } catch (RuntimeException e) { return "ERR " + e.getMessage(); }
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        String dir = args.length > 0 ? args[0] : "../../spec/conformance";
        int total = 0;
        List<String> fails = new ArrayList<>();
        for (Object o : (List<Object>) load(dir, "canonical.json").get("cases")) {
            Map<String, Object> cs = (Map<String, Object>) o;
            total++;
            String got = c(cs.get("value"));
            if (!got.equals(cs.get("canonical")) || !SmartGate.sha256(got).equals(cs.get("sha256"))) fails.add("canonical/" + cs.get("name") + ": " + got);
        }
        for (String f : new String[] {"scoring.json", "scoring-custom.json"}) {
            Map<String, Object> doc = load(dir, f);
            SmartGate.Policy p = policy(doc.get("policy"));
            for (Object o : (List<Object>) doc.get("cases")) {
                Map<String, Object> cs = (Map<String, Object>) o;
                total++;
                Object got = new SmartGate.Engine(p).decide(SmartGate.Action.parse(cs.get("action")), false, false);
                if (!c(got).equals(c(cs.get("expect")))) fails.add(f + "/" + cs.get("name") + ": " + c(got));
            }
        }
        for (Object o : (List<Object>) load(dir, "sequences.json").get("cases")) {
            Map<String, Object> cs = (Map<String, Object>) o;
            total++;
            SmartGate.Session s = new SmartGate.Session(policy(cs.get("policy")));
            List<Object> steps = (List<Object>) cs.get("steps");
            for (int i = 0; i < steps.size(); i++) {
                Map<String, Object> st = (Map<String, Object>) steps.get(i);
                Object got = s.apply(st);
                if (!c(got).equals(c(st.get("expect")))) { fails.add("sequences/" + cs.get("name") + "[" + i + "]: " + c(got)); break; }
            }
        }
        Map<String, Object> audit = load(dir, "audit.json");
        for (Object o : (List<Object>) audit.get("chains")) {
            Map<String, Object> cs = (Map<String, Object>) o;
            total++;
            List<Map<String, Object>> recs = SmartGate.chain((List<Object>) cs.get("events"));
            List<Object> hashes = new ArrayList<>();
            for (Map<String, Object> r : recs) hashes.add(r.get("hash"));
            if (!c(hashes).equals(c(cs.get("hashes"))) || SmartGate.verify(recs) != -1) fails.add("audit/" + cs.get("name"));
        }
        for (Object o : (List<Object>) audit.get("tampered")) {
            Map<String, Object> cs = (Map<String, Object>) o;
            total++;
            List<Map<String, Object>> recs = new ArrayList<>();
            for (Object r : (List<Object>) cs.get("records")) recs.add((Map<String, Object>) r);
            int idx = SmartGate.verify(recs);
            if (idx != ((Long) cs.get("bad_index")).intValue()) fails.add("audit/tampered/" + cs.get("name") + ": " + idx);
        }
        for (Object o : (List<Object>) load(dir, "policies.json").get("cases")) {
            Map<String, Object> cs = (Map<String, Object>) o;
            total++;
            boolean ok = true;
            try { SmartGate.Policy.parse(cs.get("policy")); } catch (SmartGate.PolicyError e) { ok = false; }
            if (ok != (Boolean) cs.get("valid")) fails.add("policies/" + cs.get("name") + ": valid=" + ok);
        }
        for (String f : fails) System.out.println("FAIL " + f);
        if (!fails.isEmpty()) {
            System.out.println("java: " + fails.size() + " failure(s) of " + total);
            System.exit(1);
        }
        System.out.println("java: " + total + "/" + total + " vectors passed");
    }
}

package cloud.smarttasks.smartgate;

import java.util.Map;

/** Checks the Java client against a running server (SMARTGATE_URL, SMARTGATE_AGENT_TOKEN, SMARTGATE_OPERATOR_TOKEN). */
public final class Interop {
    static void check(boolean ok, String what) {
        if (!ok) { System.out.println("FAIL " + what); System.exit(1); }
    }

    public static void main(String[] args) throws Exception {
        Client c = new Client(System.getenv("SMARTGATE_URL"), System.getenv("SMARTGATE_AGENT_TOKEN"), System.getenv("SMARTGATE_OPERATOR_TOKEN"));
        String id = "java-" + System.nanoTime();
        check("allow".equals(c.evaluate(Map.of("action_id", id + "-a", "agent_id", "java-bot", "action_type", "read")).get("decision")), "low action allowed");
        check("block".equals(c.evaluate(Map.of("action_id", id + "-b", "agent_id", "java-bot", "action_type", "delete", "reversible", false)).get("decision")), "high action blocked");
        String t = id + "-c";
        c.evaluate(Map.of("action_id", t, "agent_id", "java-bot-2", "action_type", "read"));
        check(Boolean.TRUE.equals(c.report(t, "start").get("started")), "start");
        int steps = 0;
        try {
            for (int i = 0; i < 100; i++) {
                if (i == 5) c.kill(t, "interop");
                c.checkpoint(t);
                steps++;
                Thread.sleep(10);
            }
        } catch (SmartGate.Killed k) {
            // expected
        }
        check(steps == 5, "kill reached the action");
        check(Boolean.FALSE.equals(c.kill(t, "").get("first")), "second kill is idempotent");
        System.out.println("java client: interop ok");
    }
}

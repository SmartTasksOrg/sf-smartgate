package cloud.smarttasks.smartgate;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/** Client for the SmartGate server (java.net.http). Fallback when the connection fails: "allow" (the
 *  council's default: log and run), "block", or "block_high" (score locally with the server's policy).
 *  When the request may have reached the server but no answer came (timeout), the decision is unknown and
 *  evaluate answers "block" (GATE-NO-ANSWER). HTTP errors throw ServerError. A checkpoint always asks the
 *  server, so an action admitted on the fallback still learns of a kill once the server is back. */
public final class Client {
    public final String url, agentToken, operatorToken;
    public SmartGate.Policy policy = SmartGate.Policy.defaults();
    public String fallback = policy.fallback;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();

    public static class ServerError extends RuntimeException {
        public final int status;
        ServerError(int s, String body) { super("SmartGate server answered " + s + ": " + body); status = s; }
    }

    public Client(String url, String agentToken, String operatorToken) {
        this.url = url.replaceAll("/+$", "");
        this.agentToken = agentToken;
        this.operatorToken = operatorToken;
    }

    private static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20"); }

    @SuppressWarnings("unchecked")
    public Map<String, Object> call(String method, String path, Object body, String token) throws IOException {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url + path)).timeout(Duration.ofSeconds(2))
            .header("Content-Type", "application/json")
            .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(Json.write(body)));
        if (token != null && !token.isEmpty()) b.header("Authorization", "Bearer " + token);
        HttpResponse<String> r;
        try {
            r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
        if (r.statusCode() >= 300) throw new ServerError(r.statusCode(), r.body());
        return (Map<String, Object>) Json.parse(r.body());
    }

    public Map<String, Object> evaluate(Map<String, Object> action) {
        try {
            return call("POST", "/smartgate/evaluate", action, agentToken);
        } catch (java.net.ConnectException | java.net.http.HttpConnectTimeoutException e) {
            SmartGate.Action a = SmartGate.Action.parse(action);
            long s = SmartGate.score(policy, a);
            SmartGate.Level lv = SmartGate.levelOf(policy, s);
            String d = fallback.equals("block") || (fallback.equals("block_high") && lv.friction.equals("block")) ? "block" : "allow";
            System.err.println("SmartGate unreachable (" + e.getMessage() + "); fallback " + fallback + " -> " + d);
            return Map.of("action_id", a.actionId, "agent_id", a.agentId, "decision", d, "score", s, "level", lv.name,
                "reasons", java.util.List.of("GATE-FALLBACK-" + fallback.toUpperCase(java.util.Locale.ROOT).replace("_", "-")), "cascade", false, "fallback", true);
        } catch (IOException e) {
            SmartGate.Action a = SmartGate.Action.parse(action);
            System.err.println("SmartGate did not answer (" + e.getMessage() + "); blocking " + a.actionId);
            return Map.of("action_id", a.actionId, "agent_id", a.agentId, "decision", "block",
                "reasons", java.util.List.of("GATE-NO-ANSWER"), "cascade", false);
        }
    }

    public Map<String, Object> status(String id) throws IOException { return call("GET", "/smartgate/actions/" + enc(id), null, agentToken); }
    public Map<String, Object> report(String id, String what) throws IOException { return call("POST", "/smartgate/actions/" + enc(id) + "/" + what, Map.of(), agentToken); }

    /** Throws SmartGate.Killed once the action has been killed; network errors are ignored (fallback rule). */
    public void checkpoint(String id) {
        Map<String, Object> st;
        try {
            st = status(id);
        } catch (IOException e) {
            return; // cannot ask: keep going
        } catch (ServerError e) {
            if (e.status == 404) return; // unknown to the server (admitted on the fallback)
            throw e;
        }
        if ("killed".equals(st.get("state"))) throw new SmartGate.Killed(id, String.valueOf(st.get("reason")));
    }

    public Map<String, Object> kill(String actionId, String reason) throws IOException {
        return call("POST", "/smartgate/kill", Map.of("action_id", actionId, "reason", reason), operatorToken);
    }

    public Map<String, Object> killAgent(String agentId, String reason) throws IOException {
        return call("POST", "/smartgate/kill", Map.of("agent_id", agentId, "reason", reason), operatorToken);
    }
}

using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;

namespace SmartGate;

/// <summary>Client for the SmartGate server. Fallback when the connection fails: "allow" (the council's default), "block",
/// "block_high". When the request may have reached the server but no answer came (timeout), the decision is unknown and
/// EvaluateAsync answers "block" (GATE-NO-ANSWER). A checkpoint always asks the server, so an action admitted on the
/// fallback still learns of a kill once the server is back.</summary>
public sealed class Client
{
    readonly HttpClient http = new() { Timeout = TimeSpan.FromSeconds(2) };
    public string Url { get; }
    public string AgentToken { get; }
    public string OperatorToken { get; }
    public Policy Policy { get; set; } = Policy.Default();
    public string Fallback { get; set; }

    public sealed class ServerError : Exception { public int Status { get; } public ServerError(int s, string b) : base($"SmartGate server answered {s}: {b}") { Status = s; } }

    public Client(string url, string agentToken, string operatorToken) { Url = url.TrimEnd('/'); AgentToken = agentToken; OperatorToken = operatorToken; Fallback = Policy.Fallback; }

    public async Task<JsonObject> CallAsync(HttpMethod method, string path, JsonNode? body, string token)
    {
        using var req = new HttpRequestMessage(method, Url + path);
        if (body != null) req.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        if (!string.IsNullOrEmpty(token)) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var res = await http.SendAsync(req).ConfigureAwait(false);
        var text = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
        if ((int)res.StatusCode >= 300) throw new ServerError((int)res.StatusCode, text);
        return (JsonObject)JsonNode.Parse(text)!;
    }

    public async Task<JsonObject> EvaluateAsync(JsonObject action)
    {
        try { return await CallAsync(HttpMethod.Post, "/smartgate/evaluate", action, AgentToken).ConfigureAwait(false); }
        catch (HttpRequestException e) when (e.HttpRequestError is HttpRequestError.ConnectionError or HttpRequestError.NameResolutionError)
        {
            var a = GateAction.Parse(action);
            var s = Engine.Score(Policy, a);
            var lv = Engine.LevelOf(Policy, s);
            var d = Fallback == "block" || (Fallback == "block_high" && lv.Friction == "block") ? "block" : "allow";
            Console.Error.WriteLine($"SmartGate unreachable ({e.Message}); fallback {Fallback} -> {d}");
            return new JsonObject { ["action_id"] = a.ActionId, ["agent_id"] = a.AgentId, ["decision"] = d, ["score"] = s, ["level"] = lv.Name, ["reasons"] = new JsonArray("GATE-FALLBACK-" + Fallback.ToUpperInvariant().Replace("_", "-")), ["cascade"] = false, ["fallback"] = true };
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            var a = GateAction.Parse(action);
            Console.Error.WriteLine($"SmartGate did not answer ({e.Message}); blocking {a.ActionId}");
            return new JsonObject { ["action_id"] = a.ActionId, ["agent_id"] = a.AgentId, ["decision"] = "block", ["reasons"] = new JsonArray("GATE-NO-ANSWER"), ["cascade"] = false };
        }
    }

    public Task<JsonObject> StatusAsync(string id) => CallAsync(HttpMethod.Get, "/smartgate/actions/" + Uri.EscapeDataString(id), null, AgentToken);
    public Task<JsonObject> ReportAsync(string id, string what) => CallAsync(HttpMethod.Post, $"/smartgate/actions/{Uri.EscapeDataString(id)}/{what}", new JsonObject(), AgentToken);

    /// <summary>Throws KilledException once the action has been killed; network errors are ignored.</summary>
    public async Task CheckpointAsync(string id)
    {
        JsonObject st;
        try { st = await StatusAsync(id).ConfigureAwait(false); }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { return; }
        catch (ServerError e) when (e.Status == 404) { return; }
        if (Json.Str(st["state"]) == "killed") throw new KilledException(id, Json.Str(st["reason"]) ?? "");
    }

    public Task<JsonObject> KillAsync(string actionId, string reason = "") =>
        CallAsync(HttpMethod.Post, "/smartgate/kill", new JsonObject { ["action_id"] = actionId, ["reason"] = reason }, OperatorToken);
    public Task<JsonObject> KillAgentAsync(string agentId, string reason = "") =>
        CallAsync(HttpMethod.Post, "/smartgate/kill", new JsonObject { ["agent_id"] = agentId, ["reason"] = reason }, OperatorToken);
}

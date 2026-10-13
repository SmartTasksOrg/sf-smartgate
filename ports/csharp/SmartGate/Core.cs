using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace SmartGate;

/// <summary>SmartGate for .NET: policy, decision engine, kill registry, session and audit chain (spec/SEMANTICS.md).</summary>
public sealed class PolicyError : Exception { public PolicyError(string m) : base(m) { } }
public sealed class ActionError : Exception { public ActionError(string m) : base(m) { } }
public sealed class KilledException : Exception
{
    public string ActionId { get; }
    public KilledException(string id, string reason) : base($"SmartGate killed action {id}: {reason}") { ActionId = id; }
}

public static class Json
{
    static bool IsInteger(JsonNode? n, out long v)
    {
        v = 0;
        if (n is not JsonValue jv) return false;
        var raw = jv.ToJsonString();
        if (raw.Contains('.') || raw.Contains('e') || raw.Contains('E') || raw.StartsWith('"') || raw is "true" or "false" or "null") return false;
        return long.TryParse(raw, out v);
    }
    public static bool TryInt(JsonNode? n, out long v) => IsInteger(n, out v);
    public static bool TryNum(JsonNode? n, out double v)
    {
        v = 0;
        if (n is not JsonValue jv) return false;
        var raw = jv.ToJsonString();
        if (raw.StartsWith('"') || raw is "true" or "false" or "null") return false;
        return double.TryParse(raw, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out v);
    }
    public static string? Str(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
    public static bool? Bool(JsonNode? n)
    {
        if (n is not JsonValue v) return null;
        var raw = v.ToJsonString();
        return raw == "true" ? true : raw == "false" ? false : null;
    }

    static void S(StringBuilder b, string s)
    {
        b.Append('"');
        foreach (var r in s.EnumerateRunes())
        {
            switch (r.Value)
            {
                case '"': b.Append("\\\""); break;
                case '\\': b.Append("\\\\"); break;
                case '\b': b.Append("\\b"); break;
                case '\f': b.Append("\\f"); break;
                case '\n': b.Append("\\n"); break;
                case '\r': b.Append("\\r"); break;
                case '\t': b.Append("\\t"); break;
                default:
                    if (r.Value < 0x20) b.Append($"\\u{r.Value:x4}"); else b.Append(r.ToString());
                    break;
            }
        }
        b.Append('"');
    }

    /// <summary>Canonical JSON; throws for floats and non-ASCII keys.</summary>
    public static string Canonical(JsonNode? n)
    {
        var b = new StringBuilder();
        C(b, n);
        return b.ToString();
    }

    static void C(StringBuilder b, JsonNode? n)
    {
        switch (n)
        {
            case null: b.Append("null"); break;
            case JsonObject o:
                b.Append('{');
                var first = true;
                foreach (var kv in o.OrderBy(k => k.Key, StringComparer.Ordinal))
                {
                    if (kv.Key.Any(ch => ch > 0x7f)) throw new ArgumentException("keys must be ASCII");
                    if (!first) b.Append(',');
                    first = false;
                    S(b, kv.Key);
                    b.Append(':');
                    C(b, kv.Value);
                }
                b.Append('}');
                break;
            case JsonArray a:
                b.Append('[');
                for (var i = 0; i < a.Count; i++) { if (i > 0) b.Append(','); C(b, a[i]); }
                b.Append(']');
                break;
            default:
                var s = Str(n);
                if (s != null) { S(b, s); break; }
                var bo = Bool(n);
                if (bo != null) { b.Append(bo.Value ? "true" : "false"); break; }
                if (IsInteger(n, out var l)) { b.Append(l.ToString(System.Globalization.CultureInfo.InvariantCulture)); break; }
                throw new ArgumentException("canonical JSON allows integers only");
        }
    }

    public static string Sha256(string s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
}

public sealed record Level(string Name, long MaxScore, string Friction);

public sealed class Policy
{
    public static readonly string[] Frictions = { "allow", "prompt", "block" };
    public List<(double? Max, long Score)> Bands { get; } = new();
    public Dictionary<string, long> Floors { get; } = new();
    public long DefaultFloor { get; private set; }
    public long IrreversibleBonus { get; private set; }
    public List<Level> Levels { get; } = new();
    public (long Window, long MaxActions, long MaxRisk, string Escalate)? Cascade { get; private set; }
    public (long Below, string Escalate)? LowConfidence { get; private set; }
    public long ApprovalTimeoutMs { get; private set; } = 300000;
    public string Fallback { get; private set; } = "allow";

    static long Int(JsonNode? n, string what, long lo, long hi)
    {
        if (!Json.TryInt(n, out var v)) throw new PolicyError($"{what} must be an integer");
        if (v < lo || v > hi) throw new PolicyError($"{what} must be between {lo} and {hi}");
        return v;
    }
    static string Fr(JsonNode? n, string what)
    {
        var s = Json.Str(n);
        if (s == null || !Frictions.Contains(s)) throw new PolicyError($"{what} must be one of allow, prompt, block");
        return s;
    }

    public static Policy Default()
    {
        using var st = typeof(Policy).Assembly.GetManifestResourceStream("policy.default.json")!;
        using var rd = new StreamReader(st);
        return Parse(JsonNode.Parse(rd.ReadToEnd()));
    }

    /// <summary>Validate and read a policy (spec/conformance/policies.json).</summary>
    public static Policy Parse(JsonNode? docN)
    {
        if (docN is not JsonObject doc) throw new PolicyError("policy must be a JSON object");
        if (Json.Str(doc["schema"]) != "smartgate.policy/v1") throw new PolicyError("schema must be \"smartgate.policy/v1\"");
        var p = new Policy();
        if (doc["cost_bands"] is not JsonArray bands || bands.Count == 0) throw new PolicyError("cost_bands must be a non-empty list");
        double? last = null;
        for (var i = 0; i < bands.Count; i++)
        {
            if (bands[i] is not JsonObject b) throw new PolicyError($"cost_bands[{i}] must be an object");
            var sc = Int(b["score"], $"cost_bands[{i}].score", 0, 10);
            var m = b["max_usd"];
            if (m == null)
            {
                if (i != bands.Count - 1) throw new PolicyError("only the last band may have max_usd null");
                p.Bands.Add((null, sc));
            }
            else
            {
                if (!Json.TryNum(m, out var f)) throw new PolicyError($"cost_bands[{i}].max_usd must be a number");
                if (last != null && f <= last) throw new PolicyError("cost_bands max_usd must increase");
                last = f;
                p.Bands.Add((f, sc));
            }
        }
        if (p.Bands[^1].Max != null) throw new PolicyError("the last band must have max_usd null");
        if (doc.ContainsKey("action_floors"))
        {
            if (doc["action_floors"] is not JsonObject fl) throw new PolicyError("action_floors must be an object");
            foreach (var kv in fl) p.Floors[kv.Key] = Int(kv.Value, $"action_floors.{kv.Key}", 0, 10);
        }
        if (doc.ContainsKey("default_floor")) p.DefaultFloor = Int(doc["default_floor"], "default_floor", 0, 10);
        if (doc.ContainsKey("irreversible_bonus")) p.IrreversibleBonus = Int(doc["irreversible_bonus"], "irreversible_bonus", 0, 10);
        if (doc["levels"] is not JsonArray levels || levels.Count == 0) throw new PolicyError("levels must be a non-empty list");
        long prev = -1;
        var names = new HashSet<string>();
        for (var i = 0; i < levels.Count; i++)
        {
            var name = levels[i] is JsonObject lo ? Json.Str(lo["name"]) : null;
            if (string.IsNullOrEmpty(name)) throw new PolicyError($"levels[{i}] needs a name");
            if (!names.Add(name)) throw new PolicyError($"level name {name} repeated");
            var l = (JsonObject)levels[i]!;
            var ms = Int(l["max_score"], $"levels[{i}].max_score", 0, 10);
            if (ms <= prev) throw new PolicyError("levels max_score must increase");
            prev = ms;
            p.Levels.Add(new Level(name, ms, Fr(l["friction"], $"levels[{i}].friction")));
        }
        if (prev != 10) throw new PolicyError("the last level must have max_score 10");
        if (doc["cascade"] != null)
        {
            if (doc["cascade"] is not JsonObject c) throw new PolicyError("cascade must be an object or null");
            p.Cascade = (Int(c["window_ms"], "cascade.window_ms", 1, long.MaxValue), Int(c["max_actions"], "cascade.max_actions", 1, long.MaxValue),
                Int(c["max_cumulative_risk"], "cascade.max_cumulative_risk", 0, long.MaxValue), Fr(c["escalate_to"], "cascade.escalate_to"));
        }
        if (doc["low_confidence"] != null)
        {
            if (doc["low_confidence"] is not JsonObject c) throw new PolicyError("low_confidence must be an object or null");
            p.LowConfidence = (Int(c["below_permille"], "low_confidence.below_permille", 0, 1000), Fr(c["escalate_to"], "low_confidence.escalate_to"));
        }
        if (doc.ContainsKey("approval"))
        {
            if (doc["approval"] is not JsonObject a) throw new PolicyError("approval must be an object");
            if (a.ContainsKey("timeout_ms")) p.ApprovalTimeoutMs = Int(a["timeout_ms"], "approval.timeout_ms", 1, long.MaxValue);
            if (a.ContainsKey("on_timeout") && Json.Str(a["on_timeout"]) is not ("reject" or "approve")) throw new PolicyError("approval.on_timeout must be reject or approve");
        }
        if (doc.ContainsKey("fallback"))
        {
            var f = Json.Str(doc["fallback"]);
            if (f is not ("allow" or "block" or "block_high")) throw new PolicyError("fallback must be allow, block or block_high");
            p.Fallback = f;
        }
        return p;
    }
}

public sealed class GateAction
{
    public string ActionId = "", AgentId = "", ActionType = "";
    public double CostUsd;
    public bool Reversible = true;
    public long? Confidence;
    public long TsMs;

    public static GateAction Parse(JsonNode? n)
    {
        if (n is not JsonObject o) throw new ActionError("action must be an object");
        var a = new GateAction();
        string Req(string k) { var s = Json.Str(o[k]); if (string.IsNullOrEmpty(s)) throw new ActionError($"action.{k} must be a non-empty string"); return s; }
        a.ActionId = Req("action_id"); a.AgentId = Req("agent_id"); a.ActionType = Req("action_type");
        if (o.ContainsKey("cost_usd")) { if (!Json.TryNum(o["cost_usd"], out var c) || c < 0) throw new ActionError("action.cost_usd must be a number >= 0"); a.CostUsd = c; }
        if (o.ContainsKey("reversible")) { a.Reversible = Json.Bool(o["reversible"]) ?? throw new ActionError("action.reversible must be true or false"); }
        if (o["confidence_permille"] != null) { if (!Json.TryInt(o["confidence_permille"], out var c) || c < 0 || c > 1000) throw new ActionError("action.confidence_permille must be an integer 0-1000"); a.Confidence = c; }
        if (o.ContainsKey("ts_ms")) { if (!Json.TryInt(o["ts_ms"], out var t) || t < 0) throw new ActionError("action.ts_ms must be an integer >= 0"); a.TsMs = t; }
        if (o["target"] != null && Json.Str(o["target"]) == null) throw new ActionError("action.target must be a string");
        return a;
    }
}

public sealed class Engine
{
    public Policy Policy { get; }
    readonly Dictionary<string, List<(long Ts, long Score)>> hist = new();
    readonly object gate = new();
    public Engine(Policy? p = null) { Policy = p ?? Policy.Default(); }

    static string Stronger(string a, string b) => Array.IndexOf(Policy.Frictions, a) >= Array.IndexOf(Policy.Frictions, b) ? a : b;

    public static long Score(Policy p, GateAction a)
    {
        var s = p.Bands[^1].Score;
        foreach (var (max, sc) in p.Bands) if (max == null || a.CostUsd <= max) { s = sc; break; }
        s = Math.Max(s, p.Floors.TryGetValue(a.ActionType, out var f) ? f : p.DefaultFloor);
        if (!a.Reversible) s += p.IrreversibleBonus;
        return Math.Clamp(s, 0, 10);
    }

    public static Level LevelOf(Policy p, long s) => p.Levels.FirstOrDefault(l => s <= l.MaxScore) ?? p.Levels[^1];

    public JsonObject Decide(GateAction a, bool halted = false, bool killed = false)
    {
        var s = Score(Policy, a);
        var lv = LevelOf(Policy, s);
        var fr = lv.Friction;
        var reasons = new JsonArray { "GATE-LEVEL-" + lv.Name.ToUpperInvariant() };
        if (!Policy.Floors.ContainsKey(a.ActionType)) reasons.Add("GATE-UNLISTED-TYPE");
        var cascade = false;
        if (Policy.Cascade is { } c)
        {
            lock (gate)
            {
                var h = (hist.TryGetValue(a.AgentId, out var old) ? old : new()).Where(e => e.Ts >= a.TsMs - c.Window).ToList();
                h.Add((a.TsMs, s));
                hist[a.AgentId] = h;
                cascade = h.Count > c.MaxActions && h.Sum(e => e.Score) > c.MaxRisk;
            }
            if (cascade) { fr = Stronger(fr, c.Escalate); reasons.Add("GATE-CASCADE"); }
        }
        if (Policy.LowConfidence is { } lc && a.Confidence is { } conf && conf < lc.Below) { fr = Stronger(fr, lc.Escalate); reasons.Add("GATE-LOW-CONFIDENCE"); }
        if (halted) { fr = "block"; reasons.Add("GATE-AGENT-HALTED"); }
        if (killed) { fr = "block"; reasons.Add("GATE-KILLED"); }
        return new JsonObject { ["action_id"] = a.ActionId, ["agent_id"] = a.AgentId, ["decision"] = fr, ["score"] = s, ["level"] = lv.Name, ["reasons"] = reasons, ["cascade"] = cascade };
    }
}

public sealed class Registry
{
    sealed class Rec { public string? Agent; public string State = "pending"; public string Reason = ""; }
    readonly Dictionary<string, Rec> actions = new();
    readonly Dictionary<string, bool> halted = new();
    readonly Dictionary<string, SortedSet<string>> byAgent = new();
    readonly object gate = new();

    void Index(string agent, string id) { if (!byAgent.TryGetValue(agent, out var s)) byAgent[agent] = s = new SortedSet<string>(StringComparer.Ordinal); s.Add(id); }
    public bool IsHalted(string agent) { lock (gate) return halted.TryGetValue(agent, out var h) && h; }

    public string Register(string id, string agent)
    {
        lock (gate)
        {
            if (actions.TryGetValue(id, out var cur)) { if (cur.Agent == null) { cur.Agent = agent; Index(agent, id); } return cur.State; }
            var h = halted.TryGetValue(agent, out var x) && x;
            actions[id] = new Rec { Agent = agent, State = h ? "killed" : "pending", Reason = h ? "agent_halted" : "" };
            Index(agent, id);
            return actions[id].State;
        }
    }
    public bool Start(string id) { lock (gate) { if (!actions.TryGetValue(id, out var c) || c.State is "killed" or "completed") return false; c.State = "running"; return true; } }
    public string Complete(string id) { lock (gate) { if (!actions.TryGetValue(id, out var c)) return "unknown"; if (c.State is "pending" or "running") c.State = "completed"; return c.State; } }

    JsonObject KillLocked(string id, string reason)
    {
        if (!actions.TryGetValue(id, out var c)) { actions[id] = new Rec { Agent = null, State = "killed", Reason = reason }; return new JsonObject { ["action_id"] = id, ["status"] = "killed", ["first"] = true }; }
        if (c.State == "completed") return new JsonObject { ["action_id"] = id, ["status"] = "completed", ["first"] = false, ["warning"] = "already_completed" };
        if (c.State == "killed") return new JsonObject { ["action_id"] = id, ["status"] = "killed", ["first"] = false };
        c.State = "killed"; c.Reason = reason;
        return new JsonObject { ["action_id"] = id, ["status"] = "killed", ["first"] = true };
    }
    public JsonObject Kill(string id, string reason = "") { lock (gate) return KillLocked(id, reason); }

    public JsonObject KillAgent(string agent, string reason = "")
    {
        lock (gate)
        {
            var first = !(halted.TryGetValue(agent, out var h) && h);
            halted[agent] = true;
            var killed = new JsonArray();
            foreach (var id in (byAgent.TryGetValue(agent, out var s) ? s.ToList() : new()))
            {
                var r = KillLocked(id, reason.Length == 0 ? "agent_halted" : reason);
                if (Json.Str(r["status"]) == "killed" && Json.Bool(r["first"]) == true) killed.Add(id);
            }
            return new JsonObject { ["agent_id"] = agent, ["status"] = "halted", ["first"] = first, ["killed"] = killed };
        }
    }
    public JsonObject ReleaseAgent(string agent)
    {
        lock (gate) { var first = halted.TryGetValue(agent, out var h) && h; halted[agent] = false; return new JsonObject { ["agent_id"] = agent, ["status"] = "released", ["first"] = first }; }
    }
    public void Checkpoint(string id) { lock (gate) if (actions.TryGetValue(id, out var c) && c.State == "killed") throw new KilledException(id, c.Reason); }
}

/// <summary>The deterministic core the sequence vectors run.</summary>
public sealed class Session
{
    public Engine Engine { get; }
    public Registry Registry { get; } = new();
    public Session(Policy p) { Engine = new Engine(p); }

    public JsonNode Apply(JsonObject step)
    {
        string S(string k) => Json.Str(step[k]) ?? "";
        switch (S("op"))
        {
            case "evaluate":
                var a = GateAction.Parse(step["action"]);
                var st = Registry.Register(a.ActionId, a.AgentId);
                return Engine.Decide(a, Registry.IsHalted(a.AgentId), st == "killed");
            case "kill": return Registry.Kill(S("action_id"), S("reason"));
            case "kill_agent": return Registry.KillAgent(S("agent_id"), S("reason"));
            case "release_agent": return Registry.ReleaseAgent(S("agent_id"));
            case "start": return new JsonObject { ["action_id"] = S("action_id"), ["started"] = Registry.Start(S("action_id")) };
            case "complete": return new JsonObject { ["action_id"] = S("action_id"), ["state"] = Registry.Complete(S("action_id")) };
            default: throw new ArgumentException("unknown op");
        }
    }
}

public static class Audit
{
    public const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";

    public static string RecordHash(JsonObject rec)
    {
        var body = new JsonObject();
        foreach (var kv in rec) if (kv.Key != "hash") body[kv.Key] = kv.Value?.DeepClone();
        return Json.Sha256(Json.Canonical(body));
    }

    public static List<JsonObject> Chain(JsonArray events)
    {
        var prev = Genesis;
        var outp = new List<JsonObject>();
        for (var i = 0; i < events.Count; i++)
        {
            var e = (JsonObject)events[i]!;
            var rec = e["fields"] is JsonObject f ? (JsonObject)f.DeepClone() : new JsonObject();
            rec["seq"] = i; rec["ts_ms"] = e["ts_ms"]?.DeepClone(); rec["event"] = e["event"]?.DeepClone(); rec["prev"] = prev;
            var h = RecordHash(rec);
            rec["hash"] = h;
            prev = h;
            outp.Add(rec);
        }
        return outp;
    }

    /// <summary>Index of the first bad record, or -1.</summary>
    public static int Verify(IList<JsonObject> records)
    {
        var prev = Genesis;
        for (var i = 0; i < records.Count; i++)
        {
            var r = records[i];
            if (!Json.TryInt(r["seq"], out var seq) || seq != i) return i;
            if (Json.Str(r["prev"]) != prev) return i;
            string h;
            try { h = RecordHash(r); } catch (ArgumentException) { return i; }
            if (Json.Str(r["hash"]) != h) return i;
            prev = h;
        }
        return -1;
    }
}

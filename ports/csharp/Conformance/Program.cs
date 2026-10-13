using System.Text.Json.Nodes;
using SmartGate;

// Runs spec/conformance against the .NET port: dotnet run --project Conformance -- [dir]
var dir = args.Length > 0 ? args[0] : "../../spec/conformance";
JsonObject Load(string n) => (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(dir, n)))!;
Policy Pol(JsonNode? p) => p == null || Json.Str(p) == "default" ? Policy.Default() : Policy.Parse(p);
string C(JsonNode? n) { try { return Json.Canonical(n); } catch (ArgumentException e) { return "ERR " + e.Message; } }
var total = 0;
var fails = new List<string>();
foreach (var cs in Load("canonical.json")["cases"]!.AsArray())
{
    total++;
    var got = C(cs!["value"]);
    if (got != Json.Str(cs["canonical"]) || Json.Sha256(got) != Json.Str(cs["sha256"])) fails.Add($"canonical/{cs["name"]}: {got}");
}
foreach (var f in new[] { "scoring.json", "scoring-custom.json" })
{
    var doc = Load(f);
    var p = Pol(doc["policy"]);
    foreach (var cs in doc["cases"]!.AsArray())
    {
        total++;
        var got = new Engine(p).Decide(GateAction.Parse(cs!["action"]));
        if (C(got) != C(cs["expect"])) fails.Add($"{f}/{cs["name"]}: {C(got)}");
    }
}
foreach (var cs in Load("sequences.json")["cases"]!.AsArray())
{
    total++;
    var s = new Session(Pol(cs!["policy"]));
    var steps = cs["steps"]!.AsArray();
    for (var i = 0; i < steps.Count; i++)
    {
        var got = s.Apply((JsonObject)steps[i]!);
        if (C(got) != C(steps[i]!["expect"])) { fails.Add($"sequences/{cs["name"]}[{i}]: {C(got)}"); break; }
    }
}
var audit = Load("audit.json");
foreach (var cs in audit["chains"]!.AsArray())
{
    total++;
    var recs = Audit.Chain(cs!["events"]!.AsArray());
    var hashes = new JsonArray(recs.Select(r => (JsonNode?)JsonValue.Create(Json.Str(r["hash"]))).ToArray());
    if (C(hashes) != C(cs["hashes"]) || Audit.Verify(recs) != -1) fails.Add($"audit/{cs["name"]}");
}
foreach (var cs in audit["tampered"]!.AsArray())
{
    total++;
    var recs = cs!["records"]!.AsArray().Select(r => (JsonObject)r!).ToList();
    Json.TryInt(cs["bad_index"], out var want);
    var idx = Audit.Verify(recs);
    if (idx != want) fails.Add($"audit/tampered/{cs["name"]}: {idx}");
}
foreach (var cs in Load("policies.json")["cases"]!.AsArray())
{
    total++;
    var ok = true;
    try { Policy.Parse(cs!["policy"]); } catch (PolicyError) { ok = false; }
    if (ok != Json.Bool(cs!["valid"])) fails.Add($"policies/{cs["name"]}: valid={ok}");
}
foreach (var f in fails) Console.WriteLine("FAIL " + f);
if (fails.Count > 0) { Console.WriteLine($"csharp: {fails.Count} failure(s) of {total}"); return 1; }
Console.WriteLine($"csharp: {total}/{total} vectors passed");
return 0;

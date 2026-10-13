using System.Text.Json.Nodes;
using SmartGate;

// Checks the .NET client against a running server (SMARTGATE_URL, SMARTGATE_AGENT_TOKEN, SMARTGATE_OPERATOR_TOKEN).
var c = new Client(Environment.GetEnvironmentVariable("SMARTGATE_URL")!, Environment.GetEnvironmentVariable("SMARTGATE_AGENT_TOKEN")!, Environment.GetEnvironmentVariable("SMARTGATE_OPERATOR_TOKEN")!);
void Check(bool ok, string what) { if (!ok) { Console.WriteLine("FAIL " + what); Environment.Exit(1); } }
var id = "cs-" + DateTime.UtcNow.Ticks;
var d = await c.EvaluateAsync(new JsonObject { ["action_id"] = id + "-a", ["agent_id"] = "cs-bot", ["action_type"] = "read" });
Check(Json.Str(d["decision"]) == "allow", "low action allowed");
d = await c.EvaluateAsync(new JsonObject { ["action_id"] = id + "-b", ["agent_id"] = "cs-bot", ["action_type"] = "delete", ["reversible"] = false });
Check(Json.Str(d["decision"]) == "block", "high action blocked");
var t = id + "-c";
await c.EvaluateAsync(new JsonObject { ["action_id"] = t, ["agent_id"] = "cs-bot-2", ["action_type"] = "read" });
Check(Json.Bool((await c.ReportAsync(t, "start"))["started"]) == true, "start");
var steps = 0;
try
{
    for (var i = 0; i < 100; i++)
    {
        if (i == 5) await c.KillAsync(t, "interop");
        await c.CheckpointAsync(t);
        steps++;
        await Task.Delay(10);
    }
}
catch (KilledException) { }
Check(steps == 5, "kill reached the action");
Check(Json.Bool((await c.KillAsync(t))["first"]) == false, "second kill is idempotent");
Console.WriteLine("csharp client: interop ok");
return 0;

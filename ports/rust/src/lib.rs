//! SmartGate for Rust: the decision engine, kill registry, audit chain (spec/SEMANTICS.md) and a
//! plain-HTTP client for the SmartGate server. No dependencies.
pub mod json;
pub mod sha256;

use json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;

pub const FRICTIONS: [&str; 3] = ["allow", "prompt", "block"];
const DEFAULT_POLICY: &str = include_str!("policy.default.json");

fn rank(f: &str) -> usize {
    FRICTIONS.iter().position(|x| *x == f).unwrap_or(0)
}
fn stronger<'a>(a: &'a str, b: &'a str) -> &'a str {
    if rank(a) >= rank(b) { a } else { b }
}

#[derive(Clone, Debug)]
pub struct Level {
    pub name: String,
    pub max_score: i64,
    pub friction: String,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub bands: Vec<(Option<f64>, i64)>,
    pub floors: BTreeMap<String, i64>,
    pub default_floor: i64,
    pub irreversible_bonus: i64,
    pub levels: Vec<Level>,
    pub cascade: Option<(i64, i64, i64, String)>,
    pub low_confidence: Option<(i64, String)>,
    pub approval_timeout_ms: i64,
    pub fallback: String,
}

fn int_in(v: Option<&Value>, what: &str, lo: i64, hi: i64) -> Result<i64, String> {
    match v.and_then(|x| x.as_int()) {
        Some(i) if i >= lo && i <= hi => Ok(i),
        Some(_) => Err(format!("{} must be between {} and {}", what, lo, hi)),
        None => Err(format!("{} must be an integer", what)),
    }
}
fn friction(v: Option<&Value>, what: &str) -> Result<String, String> {
    match v.and_then(|x| x.as_str()) {
        Some(s) if FRICTIONS.contains(&s) => Ok(s.to_string()),
        _ => Err(format!("{} must be one of allow, prompt, block", what)),
    }
}
fn present<'a>(m: &'a Value, k: &str) -> Option<&'a Value> {
    m.get(k)
}

impl Policy {
    pub fn default_policy() -> Policy {
        Policy::parse(&json::parse(DEFAULT_POLICY).unwrap()).unwrap()
    }

    /// Validate and read a policy document (spec/conformance/policies.json).
    pub fn parse(doc: &Value) -> Result<Policy, String> {
        if !matches!(doc, Value::Obj(_)) {
            return Err("policy must be a JSON object".into());
        }
        if doc.get("schema").and_then(|s| s.as_str()) != Some("smartgate.policy/v1") {
            return Err("schema must be \"smartgate.policy/v1\"".into());
        }
        let bands_v = doc.get("cost_bands").and_then(|b| b.as_arr()).filter(|b| !b.is_empty()).ok_or("cost_bands must be a non-empty list")?;
        let mut bands = vec![];
        let mut last: Option<f64> = None;
        for (i, b) in bands_v.iter().enumerate() {
            if !matches!(b, Value::Obj(_)) {
                return Err(format!("cost_bands[{}] must be an object", i));
            }
            let s = int_in(b.get("score"), &format!("cost_bands[{}].score", i), 0, 10)?;
            match b.get("max_usd") {
                None | Some(Value::Null) => {
                    if i != bands_v.len() - 1 {
                        return Err("only the last band may have max_usd null".into());
                    }
                    bands.push((None, s));
                }
                Some(m) => {
                    let f = m.as_num().ok_or(format!("cost_bands[{}].max_usd must be a number", i))?;
                    if let Some(l) = last {
                        if f <= l {
                            return Err("cost_bands max_usd must increase".into());
                        }
                    }
                    last = Some(f);
                    bands.push((Some(f), s));
                }
            }
        }
        if bands.last().unwrap().0.is_some() {
            return Err("the last band must have max_usd null".into());
        }
        let mut floors = BTreeMap::new();
        if let Some(f) = present(doc, "action_floors") {
            match f {
                Value::Obj(m) => {
                    for (k, v) in m {
                        floors.insert(k.clone(), int_in(Some(v), &format!("action_floors.{}", k), 0, 10)?);
                    }
                }
                _ => return Err("action_floors must be an object".into()),
            }
        }
        let default_floor = match present(doc, "default_floor") { Some(v) => int_in(Some(v), "default_floor", 0, 10)?, None => 0 };
        let irreversible_bonus = match present(doc, "irreversible_bonus") { Some(v) => int_in(Some(v), "irreversible_bonus", 0, 10)?, None => 0 };
        let lv = doc.get("levels").and_then(|l| l.as_arr()).filter(|l| !l.is_empty()).ok_or("levels must be a non-empty list")?;
        let mut levels = vec![];
        let mut prev = -1;
        let mut names = BTreeSet::new();
        for (i, l) in lv.iter().enumerate() {
            let name = l.get("name").and_then(|n| n.as_str()).filter(|n| !n.is_empty()).ok_or(format!("levels[{}] needs a name", i))?;
            if !names.insert(name.to_string()) {
                return Err(format!("level name {} repeated", name));
            }
            let ms = int_in(l.get("max_score"), &format!("levels[{}].max_score", i), 0, 10)?;
            if ms <= prev {
                return Err("levels max_score must increase".into());
            }
            prev = ms;
            let fr = friction(l.get("friction"), &format!("levels[{}].friction", i))?;
            levels.push(Level { name: name.to_string(), max_score: ms, friction: fr });
        }
        if prev != 10 {
            return Err("the last level must have max_score 10".into());
        }
        let big = i64::MAX;
        let cascade = match present(doc, "cascade") {
            None | Some(Value::Null) => None,
            Some(c @ Value::Obj(_)) => Some((
                int_in(c.get("window_ms"), "cascade.window_ms", 1, big)?,
                int_in(c.get("max_actions"), "cascade.max_actions", 1, big)?,
                int_in(c.get("max_cumulative_risk"), "cascade.max_cumulative_risk", 0, big)?,
                friction(c.get("escalate_to"), "cascade.escalate_to")?,
            )),
            _ => return Err("cascade must be an object or null".into()),
        };
        let low_confidence = match present(doc, "low_confidence") {
            None | Some(Value::Null) => None,
            Some(c @ Value::Obj(_)) => Some((
                int_in(c.get("below_permille"), "low_confidence.below_permille", 0, 1000)?,
                friction(c.get("escalate_to"), "low_confidence.escalate_to")?,
            )),
            _ => return Err("low_confidence must be an object or null".into()),
        };
        let mut approval_timeout_ms = 300000;
        match present(doc, "approval") {
            None => {}
            Some(a @ Value::Obj(_)) => {
                if let Some(t) = a.get("timeout_ms") {
                    approval_timeout_ms = int_in(Some(t), "approval.timeout_ms", 1, big)?;
                }
                if let Some(o) = a.get("on_timeout") {
                    if !matches!(o.as_str(), Some("reject") | Some("approve")) {
                        return Err("approval.on_timeout must be reject or approve".into());
                    }
                }
            }
            _ => return Err("approval must be an object".into()),
        }
        let fallback = match present(doc, "fallback") {
            None => "allow".to_string(),
            Some(f) => match f.as_str() {
                Some(s @ ("allow" | "block" | "block_high")) => s.to_string(),
                _ => return Err("fallback must be allow, block or block_high".into()),
            },
        };
        Ok(Policy { bands, floors, default_floor, irreversible_bonus, levels, cascade, low_confidence, approval_timeout_ms, fallback })
    }
}

#[derive(Clone, Debug)]
pub struct Action {
    pub action_id: String,
    pub agent_id: String,
    pub action_type: String,
    pub cost_usd: f64,
    pub reversible: bool,
    pub confidence_permille: Option<i64>,
    pub ts_ms: i64,
}

impl Action {
    pub fn parse(v: &Value) -> Result<Action, String> {
        if !matches!(v, Value::Obj(_)) {
            return Err("action must be an object".into());
        }
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).filter(|x| !x.is_empty()).map(String::from).ok_or(format!("action.{} must be a non-empty string", k));
        let cost_usd = match v.get("cost_usd") { None => 0.0, Some(c) => c.as_num().filter(|f| *f >= 0.0).ok_or("action.cost_usd must be a number >= 0")? };
        let reversible = match v.get("reversible") { None => true, Some(Value::Bool(b)) => *b, _ => return Err("action.reversible must be true or false".into()) };
        let confidence_permille = match v.get("confidence_permille") {
            None | Some(Value::Null) => None,
            Some(c) => Some(c.as_int().filter(|i| (0..=1000).contains(i)).ok_or("action.confidence_permille must be an integer 0-1000")?),
        };
        let ts_ms = match v.get("ts_ms") { None => 0, Some(t) => t.as_int().filter(|i| *i >= 0).ok_or("action.ts_ms must be an integer >= 0")? };
        if !matches!(v.get("target"), None | Some(Value::Null) | Some(Value::Str(_))) {
            return Err("action.target must be a string".into());
        }
        Ok(Action { action_id: s("action_id")?, agent_id: s("agent_id")?, action_type: s("action_type")?, cost_usd, reversible, confidence_permille, ts_ms })
    }
}

pub fn score(p: &Policy, a: &Action) -> i64 {
    let mut s = p.bands.last().unwrap().1;
    for (m, sc) in &p.bands {
        if m.map_or(true, |m| a.cost_usd <= m) {
            s = *sc;
            break;
        }
    }
    s = s.max(*p.floors.get(&a.action_type).unwrap_or(&p.default_floor));
    if !a.reversible {
        s += p.irreversible_bonus;
    }
    s.clamp(0, 10)
}

pub fn level_of(p: &Policy, s: i64) -> &Level {
    p.levels.iter().find(|l| s <= l.max_score).unwrap_or_else(|| p.levels.last().unwrap())
}

pub struct Engine {
    pub policy: Policy,
    hist: Mutex<HashMap<String, Vec<(i64, i64)>>>,
}

impl Engine {
    pub fn new(policy: Policy) -> Engine {
        Engine { policy, hist: Mutex::new(HashMap::new()) }
    }

    /// The decision as a JSON object: {action_id, agent_id, decision, score, level, reasons, cascade}.
    pub fn decide(&self, a: &Action, halted: bool, killed: bool) -> Value {
        let p = &self.policy;
        let s = score(p, a);
        let lv = level_of(p, s);
        let mut fr = lv.friction.clone();
        let mut reasons = vec![format!("GATE-LEVEL-{}", lv.name.to_uppercase())];
        if !p.floors.contains_key(&a.action_type) {
            reasons.push("GATE-UNLISTED-TYPE".into());
        }
        let mut cascade = false;
        if let Some((window, max_actions, max_risk, esc)) = &p.cascade {
            let mut hist = self.hist.lock().unwrap();
            let mut h: Vec<(i64, i64)> = hist.get(&a.agent_id).cloned().unwrap_or_default().into_iter().filter(|e| e.0 >= a.ts_ms - window).collect();
            h.push((a.ts_ms, s));
            cascade = h.len() as i64 > *max_actions && h.iter().map(|e| e.1).sum::<i64>() > *max_risk;
            hist.insert(a.agent_id.clone(), h);
            if cascade {
                fr = stronger(&fr, esc).to_string();
                reasons.push("GATE-CASCADE".into());
            }
        }
        if let (Some((below, esc)), Some(c)) = (&p.low_confidence, a.confidence_permille) {
            if c < *below {
                fr = stronger(&fr, esc).to_string();
                reasons.push("GATE-LOW-CONFIDENCE".into());
            }
        }
        if halted {
            fr = "block".into();
            reasons.push("GATE-AGENT-HALTED".into());
        }
        if killed {
            fr = "block".into();
            reasons.push("GATE-KILLED".into());
        }
        Value::obj(vec![
            ("action_id", Value::s(&a.action_id)),
            ("agent_id", Value::s(&a.agent_id)),
            ("decision", Value::Str(fr)),
            ("score", Value::Int(s)),
            ("level", Value::s(&lv.name)),
            ("reasons", Value::Arr(reasons.into_iter().map(Value::Str).collect())),
            ("cascade", Value::Bool(cascade)),
        ])
    }
}

#[derive(Default)]
pub struct Registry {
    actions: BTreeMap<String, (Option<String>, String, String)>, // agent, state, reason
    halted: BTreeMap<String, bool>,
    by_agent: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug)]
pub struct Killed {
    pub action_id: String,
    pub reason: String,
}

impl Registry {
    pub fn is_halted(&self, agent: &str) -> bool {
        *self.halted.get(agent).unwrap_or(&false)
    }
    pub fn register(&mut self, id: &str, agent: &str) -> String {
        if let Some(cur) = self.actions.get_mut(id) {
            if cur.0.is_none() {
                cur.0 = Some(agent.to_string());
                self.by_agent.entry(agent.to_string()).or_default().insert(id.to_string());
            }
            return cur.1.clone();
        }
        let (st, reason) = if self.is_halted(agent) { ("killed", "agent_halted") } else { ("pending", "") };
        self.actions.insert(id.into(), (Some(agent.into()), st.into(), reason.into()));
        self.by_agent.entry(agent.to_string()).or_default().insert(id.to_string());
        st.into()
    }
    pub fn start(&mut self, id: &str) -> bool {
        match self.actions.get_mut(id) {
            Some(cur) if cur.1 != "killed" && cur.1 != "completed" => {
                cur.1 = "running".into();
                true
            }
            _ => false,
        }
    }
    pub fn complete(&mut self, id: &str) -> String {
        match self.actions.get_mut(id) {
            None => "unknown".into(),
            Some(cur) => {
                if cur.1 == "pending" || cur.1 == "running" {
                    cur.1 = "completed".into();
                }
                cur.1.clone()
            }
        }
    }
    pub fn kill(&mut self, id: &str, reason: &str) -> Value {
        let r = |status: &str, first: bool| Value::obj(vec![("action_id", Value::s(id)), ("status", Value::s(status)), ("first", Value::Bool(first))]);
        match self.actions.get_mut(id) {
            None => {
                self.actions.insert(id.into(), (None, "killed".into(), reason.into()));
                r("killed", true)
            }
            Some(cur) if cur.1 == "completed" => Value::obj(vec![
                ("action_id", Value::s(id)),
                ("status", Value::s("completed")),
                ("first", Value::Bool(false)),
                ("warning", Value::s("already_completed")),
            ]),
            Some(cur) if cur.1 == "killed" => r("killed", false),
            Some(cur) => {
                cur.1 = "killed".into();
                cur.2 = reason.into();
                r("killed", true)
            }
        }
    }
    pub fn kill_agent(&mut self, agent: &str, reason: &str) -> Value {
        let first = !self.is_halted(agent);
        self.halted.insert(agent.into(), true);
        let reason = if reason.is_empty() { "agent_halted" } else { reason };
        let ids: Vec<String> = self.by_agent.get(agent).cloned().unwrap_or_default().into_iter().collect();
        let mut killed = vec![];
        for id in ids {
            let r = self.kill(&id, reason);
            if r.get("status") == Some(&Value::s("killed")) && r.get("first") == Some(&Value::Bool(true)) {
                killed.push(Value::Str(id));
            }
        }
        Value::obj(vec![("agent_id", Value::s(agent)), ("status", Value::s("halted")), ("first", Value::Bool(first)), ("killed", Value::Arr(killed))])
    }
    pub fn release_agent(&mut self, agent: &str) -> Value {
        let first = self.is_halted(agent);
        self.halted.insert(agent.into(), false);
        Value::obj(vec![("agent_id", Value::s(agent)), ("status", Value::s("released")), ("first", Value::Bool(first))])
    }
    pub fn checkpoint(&self, id: &str) -> Result<(), Killed> {
        match self.actions.get(id) {
            Some(cur) if cur.1 == "killed" => Err(Killed { action_id: id.into(), reason: cur.2.clone() }),
            _ => Ok(()),
        }
    }
}

/// The deterministic core the sequence vectors run.
pub struct Session {
    pub engine: Engine,
    pub registry: Registry,
}

impl Session {
    pub fn new(p: Policy) -> Session {
        Session { engine: Engine::new(p), registry: Registry::default() }
    }
    pub fn apply(&mut self, step: &Value) -> Result<Value, String> {
        let s = |k: &str| step.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let r = &mut self.registry;
        Ok(match step.get("op").and_then(|o| o.as_str()) {
            Some("evaluate") => {
                let a = Action::parse(step.get("action").ok_or("no action")?)?;
                let st = r.register(&a.action_id, &a.agent_id);
                let halted = r.is_halted(&a.agent_id);
                self.engine.decide(&a, halted, st == "killed")
            }
            Some("kill") => r.kill(&s("action_id"), &s("reason")),
            Some("kill_agent") => r.kill_agent(&s("agent_id"), &s("reason")),
            Some("release_agent") => r.release_agent(&s("agent_id")),
            Some("start") => Value::obj(vec![("action_id", Value::Str(s("action_id"))), ("started", Value::Bool(r.start(&s("action_id"))))]),
            Some("complete") => Value::obj(vec![("action_id", Value::Str(s("action_id"))), ("state", Value::Str(r.complete(&s("action_id"))))]),
            _ => return Err("unknown op".into()),
        })
    }
}

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn record_hash(rec: &Value) -> Result<String, String> {
    let mut body = match rec {
        Value::Obj(m) => m.clone(),
        _ => return Err("record must be an object".into()),
    };
    body.remove("hash");
    Ok(sha256::hex(json::canonical(&Value::Obj(body))?.as_bytes()))
}

/// Build the records of an audit chain from [{event, ts_ms, fields}].
pub fn chain(events: &[Value]) -> Result<Vec<Value>, String> {
    let mut prev = GENESIS.to_string();
    let mut out = vec![];
    for (i, e) in events.iter().enumerate() {
        let mut m = match e.get("fields") {
            Some(Value::Obj(f)) => f.clone(),
            _ => BTreeMap::new(),
        };
        m.insert("seq".into(), Value::Int(i as i64));
        m.insert("ts_ms".into(), e.get("ts_ms").cloned().unwrap_or(Value::Int(0)));
        m.insert("event".into(), e.get("event").cloned().unwrap_or(Value::Null));
        m.insert("prev".into(), Value::Str(prev.clone()));
        let h = record_hash(&Value::Obj(m.clone()))?;
        m.insert("hash".into(), Value::Str(h.clone()));
        prev = h;
        out.push(Value::Obj(m));
    }
    Ok(out)
}

/// Index of the first bad record, or None when the chain verifies.
pub fn verify(records: &[Value]) -> Option<usize> {
    let mut prev = GENESIS.to_string();
    for (i, r) in records.iter().enumerate() {
        if r.get("seq").and_then(|s| s.as_int()) != Some(i as i64) {
            return Some(i);
        }
        if r.get("prev").and_then(|s| s.as_str()) != Some(prev.as_str()) {
            return Some(i);
        }
        match record_hash(r) {
            Ok(h) if r.get("hash").and_then(|s| s.as_str()) == Some(h.as_str()) => prev = h,
            _ => return Some(i),
        }
    }
    None
}

pub mod client;

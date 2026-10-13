//! cargo run --bin conformance [dir]
use smartgate::json::{self, canonical, Value};
use smartgate::{chain, sha256, verify, Action, Engine, Policy, Session};

fn load(dir: &str, n: &str) -> Value {
    json::parse(&std::fs::read_to_string(format!("{}/{}", dir, n)).unwrap()).unwrap()
}
fn policy(v: Option<&Value>) -> Policy {
    match v {
        None | Some(Value::Null) => Policy::default_policy(),
        Some(Value::Str(s)) if s == "default" => Policy::default_policy(),
        Some(p) => Policy::parse(p).unwrap(),
    }
}
fn c(v: &Value) -> String {
    canonical(v).unwrap_or_else(|e| format!("ERR {}", e))
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or("../../spec/conformance".into());
    let mut total = 0;
    let mut fails: Vec<String> = vec![];
    for cs in load(&dir, "canonical.json").get("cases").unwrap().as_arr().unwrap() {
        total += 1;
        let got = c(cs.get("value").unwrap());
        if Some(got.as_str()) != cs.get("canonical").unwrap().as_str() || Some(sha256::hex(got.as_bytes()).as_str()) != cs.get("sha256").unwrap().as_str() {
            fails.push(format!("canonical/{}: {}", c(cs.get("name").unwrap()), got));
        }
    }
    for f in ["scoring.json", "scoring-custom.json"] {
        let doc = load(&dir, f);
        let p = policy(doc.get("policy"));
        for cs in doc.get("cases").unwrap().as_arr().unwrap() {
            total += 1;
            let a = Action::parse(cs.get("action").unwrap()).unwrap();
            let got = Engine::new(p.clone()).decide(&a, false, false);
            if c(&got) != c(cs.get("expect").unwrap()) {
                fails.push(format!("{}/{}: {}", f, c(cs.get("name").unwrap()), c(&got)));
            }
        }
    }
    for cs in load(&dir, "sequences.json").get("cases").unwrap().as_arr().unwrap() {
        total += 1;
        let mut s = Session::new(policy(cs.get("policy")));
        for (i, st) in cs.get("steps").unwrap().as_arr().unwrap().iter().enumerate() {
            let got = s.apply(st).unwrap();
            if c(&got) != c(st.get("expect").unwrap()) {
                fails.push(format!("sequences/{}[{}]: {}", c(cs.get("name").unwrap()), i, c(&got)));
                break;
            }
        }
    }
    let audit = load(&dir, "audit.json");
    for cs in audit.get("chains").unwrap().as_arr().unwrap() {
        total += 1;
        let recs = chain(cs.get("events").unwrap().as_arr().unwrap()).unwrap();
        let hashes = Value::Arr(recs.iter().map(|r| r.get("hash").unwrap().clone()).collect());
        if c(&hashes) != c(cs.get("hashes").unwrap()) || verify(&recs).is_some() {
            fails.push(format!("audit/{}", c(cs.get("name").unwrap())));
        }
    }
    for cs in audit.get("tampered").unwrap().as_arr().unwrap() {
        total += 1;
        let idx = verify(cs.get("records").unwrap().as_arr().unwrap());
        if idx.map(|i| i as i64) != cs.get("bad_index").unwrap().as_int() {
            fails.push(format!("audit/tampered/{}: {:?}", c(cs.get("name").unwrap()), idx));
        }
    }
    for cs in load(&dir, "policies.json").get("cases").unwrap().as_arr().unwrap() {
        total += 1;
        let ok = Policy::parse(cs.get("policy").unwrap()).is_ok();
        if Some(&Value::Bool(ok)) != cs.get("valid") {
            fails.push(format!("policies/{}: valid={}", c(cs.get("name").unwrap()), ok));
        }
    }
    for f in &fails {
        println!("FAIL {}", f);
    }
    if fails.is_empty() {
        println!("rust: {}/{} vectors passed", total, total);
    } else {
        println!("rust: {} failure(s) of {}", fails.len(), total);
        std::process::exit(1);
    }
}

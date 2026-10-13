//! Checks the Rust client against a running server (SMARTGATE_URL, SMARTGATE_AGENT_TOKEN, SMARTGATE_OPERATOR_TOKEN).
use smartgate::client::{Client, Error};
use smartgate::json::Value;
use std::time::{Duration, SystemTime};

fn check(ok: bool, what: &str) {
    if !ok {
        println!("FAIL {}", what);
        std::process::exit(1);
    }
}

fn main() {
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let c = Client::new(&env("SMARTGATE_URL"), &env("SMARTGATE_AGENT_TOKEN"), &env("SMARTGATE_OPERATOR_TOKEN")).unwrap();
    let id = format!("rust-{}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos());
    let act = |suffix: &str, extra: Vec<(&str, Value)>| {
        let mut v = vec![("action_id", Value::Str(format!("{}-{}", id, suffix))), ("agent_id", Value::s("rust-bot")), ("action_type", Value::s("read"))];
        v.extend(extra);
        Value::obj(v)
    };
    let d = c.evaluate(&act("a", vec![])).unwrap();
    check(d.get("decision") == Some(&Value::s("allow")), "low action allowed");
    let d = c.evaluate(&act("b", vec![("action_type", Value::s("delete")), ("reversible", Value::Bool(false))])).unwrap();
    check(d.get("decision") == Some(&Value::s("block")), "high action blocked");
    let target = format!("{}-c x:y", id);
    c.evaluate(&Value::obj(vec![("action_id", Value::s(&target)), ("agent_id", Value::s("rust-bot-2")), ("action_type", Value::s("read"))])).unwrap();
    check(c.report(&target, "start").unwrap().get("started") == Some(&Value::Bool(true)), "start");
    let mut steps = 0;
    for i in 0..100 {
        if i == 5 {
            c.kill(&target, "interop").unwrap();
        }
        if !c.checkpoint(&target).unwrap() {
            break;
        }
        steps += 1;
        std::thread::sleep(Duration::from_millis(10));
    }
    check(steps == 5, "kill reached the action");
    let again = c.kill(&target, "").unwrap();
    check(again.get("first") == Some(&Value::Bool(false)), "second kill is idempotent");
    check(matches!(Client::new("http://127.0.0.1:9", "", "").unwrap().status("x"), Err(Error::Network(_))), "network error reported");
    println!("rust client: interop ok");
}

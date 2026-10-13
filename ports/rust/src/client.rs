//! A plain-HTTP client for the SmartGate server (std only). For TLS, run the client next to a local
//! TLS-terminating proxy or use your HTTP stack with the same endpoints (spec/openapi.yaml).
use crate::json::{self, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct Client {
    host: String,
    port: u16,
    pub agent_token: String,
    pub operator_token: String,
    pub timeout: Duration,
}

#[derive(Debug)]
pub enum Error {
    Network(String),
    Server(u16, String),
}

/// Percent-encode one path segment (RFC 3986 unreserved characters are kept).
pub fn seg(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{:02X}", b) })
        .collect()
}

impl Client {
    pub fn new(url: &str, agent_token: &str, operator_token: &str) -> Result<Client, String> {
        let rest = url.strip_prefix("http://").ok_or("only http:// URLs are supported by this client")?;
        let hostport = rest.split('/').next().unwrap_or("");
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().map_err(|_| "bad port")?),
            None => (hostport.to_string(), 80),
        };
        Ok(Client { host, port, agent_token: agent_token.into(), operator_token: operator_token.into(), timeout: Duration::from_secs(2) })
    }

    pub fn call(&self, method: &str, path: &str, body: Option<&Value>, token: &str) -> Result<Value, Error> {
        let net = |e: std::io::Error| Error::Network(e.to_string());
        let addr = format!("{}:{}", self.host, self.port);
        let mut s = TcpStream::connect(&addr).map_err(net)?;
        s.set_read_timeout(Some(self.timeout)).map_err(net)?;
        s.set_write_timeout(Some(self.timeout)).map_err(net)?;
        let data = body.map(json::to_json).unwrap_or_default();
        let mut req = format!("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n", method, path, addr, data.len());
        if !token.is_empty() {
            req.push_str(&format!("Authorization: Bearer {}\r\n", token));
        }
        req.push_str("\r\n");
        req.push_str(&data);
        s.write_all(req.as_bytes()).map_err(net)?;
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).map_err(net)?;
        let text = String::from_utf8_lossy(&resp).to_string();
        let (head, body) = text.split_once("\r\n\r\n").ok_or(Error::Network("bad response".into()))?;
        let status: u16 = head.split_whitespace().nth(1).and_then(|x| x.parse().ok()).ok_or(Error::Network("bad status".into()))?;
        if status >= 300 {
            return Err(Error::Server(status, body.to_string()));
        }
        json::parse(body).map_err(Error::Network)
    }

    pub fn evaluate(&self, action: &Value) -> Result<Value, Error> {
        self.call("POST", "/smartgate/evaluate", Some(action), &self.agent_token)
    }
    pub fn status(&self, id: &str) -> Result<Value, Error> {
        self.call("GET", &format!("/smartgate/actions/{}", seg(id)), None, &self.agent_token)
    }
    pub fn report(&self, id: &str, what: &str) -> Result<Value, Error> {
        self.call("POST", &format!("/smartgate/actions/{}/{}", seg(id), what), Some(&Value::obj(vec![])), &self.agent_token)
    }
    /// Ok(true) while the action may continue, Ok(false) once it has been killed.
    pub fn checkpoint(&self, id: &str) -> Result<bool, Error> {
        Ok(self.status(id)?.get("state").and_then(|s| s.as_str()) != Some("killed"))
    }
    pub fn kill(&self, action_id: &str, reason: &str) -> Result<Value, Error> {
        let b = Value::obj(vec![("action_id", Value::s(action_id)), ("reason", Value::s(reason))]);
        self.call("POST", "/smartgate/kill", Some(&b), &self.operator_token)
    }
    pub fn kill_agent(&self, agent_id: &str, reason: &str) -> Result<Value, Error> {
        let b = Value::obj(vec![("agent_id", Value::s(agent_id)), ("reason", Value::s(reason))]);
        self.call("POST", "/smartgate/kill", Some(&b), &self.operator_token)
    }
}

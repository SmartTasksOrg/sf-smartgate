"""The SmartGate server: REST API, kill switch, approvals, Slack clicks and /metrics (stdlib only).

    sf-smartgate serve --host 0.0.0.0 --port 8711 --policy policy.json --audit audit.jsonl

Tokens (required unless --insecure-dev, which binds 127.0.0.1 only):
    SMARTGATE_AGENT_TOKEN     agents: evaluate, report start/complete, read status and approvals
    SMARTGATE_OPERATOR_TOKEN  people: kill, halt/release agents, approve/reject
Operator endpoints check the IP allowlist first (SMARTGATE_KILL_ALLOW: comma-separated addresses or
CIDRs, when set), then the token, then a per-IP rate limit: kills have their own bucket (--kill-rate,
default 10 per minute), approve/reject/release share another (60 per minute). Failed token checks are
rate-limited too (20 per minute per IP). /slack/actions is protected by Slack's request signature, not
by the allowlist (Slack calls from its own addresses), and has its own rate limit.
Requests: at most 64 KiB, Content-Length required (no chunked bodies), 10 s socket timeout, at most
256 connections handled at once, each closed after 30 s; every error answer closes the connection.
These limits protect the process, not the service: put the server behind a proxy with connection limits.
Optional: SMARTGATE_REDIS_URL (shared state for several servers; ``pip install redis``),
SMARTGATE_SLACK_* (see slack.py). Spec: spec/openapi.yaml.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import canonical

from . import __version__, slack
from .audit import AuditLog
from .engine import ActionError
from .gate import Gate
from .policy import Policy, PolicyError

log = logging.getLogger('sf_smartgate.server')
MAX_BODY = 64 * 1024


class RateLimiter:
    """Token bucket per key: ``rate`` requests per ``per_s`` seconds."""

    def __init__(self, rate: int = 10, per_s: float = 60.0, clock=time.monotonic):
        self.rate, self.per_s, self.clock = rate, per_s, clock
        self._b: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self.clock()
        with self._lock:
            tokens, last = self._b.get(key, (float(self.rate), now))
            tokens = min(self.rate, tokens + (now - last) * self.rate / self.per_s)
            if tokens < 1:
                self._b[key] = (tokens, now)
                return False
            self._b[key] = (tokens - 1, now)
            return True


def parse_allowlist(text: str | None):
    if not text:
        return None
    return [ipaddress.ip_network(x.strip(), strict=False) for x in text.split(',') if x.strip()]


def ip_allowed(ip: str, nets) -> bool:
    if nets is None:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


REQUEST_ID_TTL_MS = 24 * 3600 * 1000


class Config:
    def __init__(self, agent_token=None, operator_token=None, kill_rate=10, kill_allow=None,
                 slack_signing_secret=None, insecure_dev=False, operator_rate=60, auth_fail_rate=20, slack_rate=60):
        self.agent_token, self.operator_token = agent_token, operator_token
        self.kill_limiter = RateLimiter(kill_rate, 60.0)
        self.operator_limiter = RateLimiter(operator_rate, 60.0)
        self.auth_fail_limiter = RateLimiter(auth_fail_rate, 60.0)
        self.slack_limiter = RateLimiter(slack_rate, 60.0)
        self.kill_allow = parse_allowlist(kill_allow) if isinstance(kill_allow, str) else kill_allow
        self.slack_signing_secret = slack_signing_secret
        self.insecure_dev = insecure_dev

    @classmethod
    def from_env(cls, insecure_dev=False, kill_rate=10):
        e = os.environ
        return cls(e.get('SMARTGATE_AGENT_TOKEN'), e.get('SMARTGATE_OPERATOR_TOKEN'), kill_rate,
                   e.get('SMARTGATE_KILL_ALLOW'), e.get('SMARTGATE_SLACK_SIGNING_SECRET'), insecure_dev)


ROUTES = [
    ('GET', re.compile(r'^/healthz$'), 'healthz', None),
    ('GET', re.compile(r'^/metrics$'), 'metrics', None),
    ('POST', re.compile(r'^/smartgate/score$'), 'score', 'agent'),
    ('POST', re.compile(r'^/smartgate/evaluate$'), 'evaluate', 'agent'),
    ('GET', re.compile(r'^/smartgate/actions/(?P<id>[^/]+)$'), 'action_status', 'agent'),
    ('POST', re.compile(r'^/smartgate/actions/(?P<id>[^/]+)/(?P<what>start|complete)$'), 'action_report', 'agent'),
    ('GET', re.compile(r'^/smartgate/approvals/(?P<id>[^/]+)$'), 'approval_get', 'agent'),
    ('POST', re.compile(r'^/smartgate/approvals/(?P<id>[^/]+)/(?P<what>approve|reject)$'), 'approval_set', 'operator'),
    ('POST', re.compile(r'^/smartgate/kill$'), 'kill', 'operator'),
    ('POST', re.compile(r'^/smartgate/agents/(?P<id>[^/]+)/release$'), 'release', 'operator'),
    ('POST', re.compile(r'^/slack/actions$'), 'slack', 'slack'),
]


def make_handler(gate: Gate, cfg: Config):
    class H(BaseHTTPRequestHandler):
        server_version = 'sf-smartgate/' + __version__
        protocol_version = 'HTTP/1.1'
        timeout = 10            # seconds per socket operation: slow clients cannot hold a thread

        def log_message(self, fmt, *args):  # route through logging
            log.info('%s %s', self.client_address[0], fmt % args)

        def _send(self, code, obj, ctype='application/json'):
            body = obj.encode() if isinstance(obj, str) else json.dumps(obj).encode()
            if code >= 400:      # the request body may be unread: never reuse this connection
                self.close_connection = True
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            if code >= 400:
                self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> bytes:
            if self.headers.get('Transfer-Encoding'):
                raise _HTTPError(411, 'send Content-Length; chunked bodies are not accepted')
            raw = self.headers.get('Content-Length') or '0'
            if not raw.isdigit() or int(raw) > MAX_BODY:
                raise _HTTPError(413, 'request body too large or Content-Length invalid')
            n = int(raw)
            return self.rfile.read(n) if n else b''

        def _json(self, raw: bytes):
            if not raw:
                return {}
            v = json.loads(raw)
            if not isinstance(v, dict):
                raise ValueError('body must be a JSON object')
            return v

        def _token_ok(self, role):
            if cfg.insecure_dev:
                return True
            want = cfg.agent_token if role == 'agent' else cfg.operator_token
            got = self.headers.get('Authorization', '')
            if not want or not got.startswith('Bearer '):
                return False
            # operators may also do agent things (read status)
            if role == 'agent' and cfg.operator_token and hmac.compare_digest(got[7:], cfg.operator_token):
                return True
            return hmac.compare_digest(got[7:], want)

        def _is_operator(self):
            got = self.headers.get('Authorization', '')
            return bool(cfg.operator_token) and got.startswith('Bearer ') and hmac.compare_digest(got[7:], cfg.operator_token)

        def _dispatch(self, method):
            path = self.path.split('?', 1)[0]
            ip = self.client_address[0]
            for m, rx, name, role in ROUTES:
                mt = rx.match(path)
                if mt and m == method:
                    try:
                        if role == 'operator' and not ip_allowed(ip, cfg.kill_allow):
                            return self._send(403, {'error': 'source address not allowed'})
                        if role in ('agent', 'operator') and not self._token_ok(role):
                            if not cfg.auth_fail_limiter.allow(ip):
                                return self._send(429, {'error': 'rate limit'})
                            return self._send(401, {'error': 'missing or wrong bearer token'})
                        if role == 'operator':
                            lim = cfg.kill_limiter if name == 'kill' else cfg.operator_limiter
                            if not lim.allow(ip):
                                return self._send(429, {'error': 'rate limit'})
                        if role == 'slack' and not cfg.slack_limiter.allow(ip):
                            return self._send(429, {'error': 'rate limit'})
                        if method == 'GET' and (self.headers.get('Transfer-Encoding') or
                                                (self.headers.get('Content-Length') or '0') != '0'):
                            raise _HTTPError(400, 'GET requests have no body')
                        raw = self._body() if method == 'POST' else b''
                        params = {k: urllib.parse.unquote(v) for k, v in mt.groupdict().items()}
                        return getattr(self, 'r_' + name)(raw, **params)
                    except _HTTPError as e:
                        return self._send(e.code, {'error': str(e)})
                    except (ValueError, ActionError) as e:
                        return self._send(400, {'error': str(e)})
                    except Exception:
                        log.exception('handler failed')
                        return self._send(500, {'error': 'internal error'})
            return self._send(404, {'error': 'not found'})

        def do_GET(self):
            self._dispatch('GET')

        def do_POST(self):
            self._dispatch('POST')

        # -- routes
        def r_healthz(self, raw):
            self._send(200, {'ok': True, 'version': __version__})

        def r_metrics(self, raw):
            self._send(200, gate.metrics.expose(), 'text/plain; version=0.0.4')

        def r_score(self, raw):
            self._send(200, gate.score(self._json(raw)))

        def r_evaluate(self, raw):
            self._send(200, gate.evaluate(self._json(raw)))

        def r_action_status(self, raw, id):
            st = gate.registry.status(id)
            if st is None:
                return self._send(404, {'error': 'unknown action'})
            if st['state'] == 'killed' and not self._is_operator():
                gate.registry.ack(id)            # the agent is being told now: time to override
            self._send(200, {k: st.get(k) for k in ('action_id', 'agent_id', 'state', 'reason')})

        def r_action_report(self, raw, id, what):
            if what == 'start':
                ok = gate.start(id)              # refuses blocked, unapproved and killed actions
                gate.audit.append('action_start', action_id=id, started=ok)
                return self._send(200, {'action_id': id, 'started': ok})
            state = gate.registry.complete(id)
            gate.audit.append('action_end', action_id=id, state=state, error=None)
            self._send(200, {'action_id': id, 'state': state})

        def r_approval_get(self, raw, id):
            a = gate.approvals.get(id)
            self._send(200, a) if a else self._send(404, {'error': 'unknown approval'})

        def r_approval_set(self, raw, id, what):
            r = gate.approve(id, 'operator') if what == 'approve' else gate.reject(id, 'operator')
            self._send(200, r) if r else self._send(404, {'error': 'unknown approval'})

        def _do_kill(self, body):
            reason = str(body.get('reason', ''))[:500]
            if body.get('agent_id') and body.get('action_id'):
                raise ValueError('give action_id or agent_id, not both')
            if body.get('agent_id'):
                return gate.kill_agent(str(body['agent_id']), reason, 'operator')
            if body.get('action_id'):
                aid = str(body['action_id'])
                seen = gate.registry.status(aid)
                r = gate.kill(aid, reason, 'operator')
                # seen: false means SmartGate never registered this action (it is kept as a tombstone, so
                # the action is refused if it arrives; an agent running on its fallback learns of the kill
                # at its next checkpoint once it reaches the server)
                r['seen'] = bool(seen and seen.get('agent_id'))
                return r
            raise ValueError('give action_id or agent_id')

        def r_kill(self, raw):
            body = self._json(raw)
            rid = self.headers.get('X-Request-ID')
            if not rid:
                return self._send(200, self._do_kill(body))
            if len(rid) > 200:
                raise ValueError('X-Request-ID too long')
            digest = hashlib.sha256(canonical.encode({'body': body}) if _canonicalisable(body) else raw).hexdigest()
            key = 'killreq:' + rid
            with gate.store.lock(key):
                prev = gate.store.get(key)
                now = gate.clock()
                if prev is not None and now - prev['at_ms'] < REQUEST_ID_TTL_MS:
                    if prev['body_sha256'] != digest:
                        return self._send(409, {'error': 'X-Request-ID was used for a different request'})
                    return self._send(200, prev['response'])
                r = self._do_kill(body)
                gate.store.put(key, {'body_sha256': digest, 'response': r, 'at_ms': now})
            self._send(200, r)

        def r_release(self, raw, id):
            self._send(200, gate.release_agent(id, 'operator'))

        def r_slack(self, raw):
            secret = cfg.slack_signing_secret
            if not secret or not slack.verify_signature(secret, self.headers.get('X-Slack-Request-Timestamp'),
                                                        raw, self.headers.get('X-Slack-Signature')):
                return self._send(401, {'error': 'bad Slack signature'})
            try:
                button, approval_id, action_id, user = slack.parse_click(raw)
            except (KeyError, IndexError, TypeError, ValueError):
                return self._send(400, {'error': 'not a Slack button payload'})
            if not all(isinstance(x, str) and x for x in (button, approval_id, action_id)):
                return self._send(400, {'error': 'not a Slack button payload'})
            seen_key = 'slackreq:' + hashlib.sha256(self.headers.get('X-Slack-Signature', '').encode()).hexdigest()
            with gate.store.lock(seen_key):
                if gate.store.get(seen_key) is not None:      # the same signed request again (a replay or a retry)
                    return self._send(200, {'replace_original': False, 'text': 'Already handled.'})
                text = self._slack_act(button, approval_id, action_id, user)
                if text is None:
                    return self._send(400, {'error': 'unknown button'})
                gate.store.put(seen_key, {'at_ms': gate.clock()})   # only after the click was handled
            self._send(200, {'replace_original': False, 'text': text})

        def _slack_act(self, button, approval_id, action_id, user):
            by = 'slack:' + user
            if button == slack.APPROVE:
                r = gate.approve(approval_id, by)
                text = f'Approved by <@{user}>' if r and r['state'] == 'approved' else f"Not approved: the request is {r['state'] if r else 'unknown'}"
            elif button == slack.REJECT:
                r = gate.reject(approval_id, by)
                text = f'Rejected by <@{user}>' if r and r['state'] == 'rejected' else f"The request is already {r['state'] if r else 'unknown'}"
            elif button == slack.KILL:
                gate.reject(approval_id, by)
                k = gate.kill(action_id, 'killed from Slack', by)
                text = f"Killed by <@{user}>" if k['status'] == 'killed' else f"Not killed: the action is {k['status']}"
            else:
                return None
            return text

    return H


def build_gate(policy_path=None, audit_path=None, redis_url=None, slack_env=True) -> Gate:
    policy = Policy.load(policy_path) if policy_path else Policy()
    store = None
    if redis_url:
        import redis  # optional dependency
        from .registry import RedisStore
        store = RedisStore(redis.Redis.from_url(redis_url))
    notifier = None
    e = os.environ
    if slack_env and (e.get('SMARTGATE_SLACK_WEBHOOK_URL') or e.get('SMARTGATE_SLACK_BOT_TOKEN')):
        notifier = slack.SlackNotifier(e.get('SMARTGATE_SLACK_WEBHOOK_URL'), e.get('SMARTGATE_SLACK_BOT_TOKEN'),
                                       e.get('SMARTGATE_SLACK_CHANNEL'))
    return Gate(policy, store=store, audit=AuditLog(audit_path), notifier=notifier)


class _HTTPError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


def _canonicalisable(v) -> bool:
    try:
        canonical.dumps(v)
        return True
    except TypeError:
        return False


CONNECTION_DEADLINE_S = 30


def _close_quietly(sock):
    import socket
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class SmartGateHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a cap on requests handled at once (extra connections are closed)."""
    daemon_threads = True

    def __init__(self, addr, handler, max_threads=256):
        super().__init__(addr, handler)
        self._slots = threading.BoundedSemaphore(max_threads)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        # a connection may live at most CONNECTION_DEADLINE_S, however slowly its bytes arrive
        watchdog = threading.Timer(CONNECTION_DEADLINE_S, _close_quietly, args=(request,))
        watchdog.daemon = True
        watchdog.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            watchdog.cancel()
            self._slots.release()


def make_server(gate: Gate, cfg: Config, host='127.0.0.1', port=8711) -> ThreadingHTTPServer:
    if not cfg.insecure_dev and not (cfg.agent_token and cfg.operator_token):
        raise SystemExit('set SMARTGATE_AGENT_TOKEN and SMARTGATE_OPERATOR_TOKEN (or use --insecure-dev on 127.0.0.1)')
    if cfg.insecure_dev and host not in ('127.0.0.1', 'localhost', '::1'):
        raise SystemExit('--insecure-dev only binds 127.0.0.1')
    return SmartGateHTTPServer((host, port), make_handler(gate, cfg))


def serve(host, port, policy_path=None, audit_path=None, insecure_dev=False, kill_rate=10):
    try:
        gate = build_gate(policy_path, audit_path, os.environ.get('SMARTGATE_REDIS_URL'))
    except PolicyError as e:
        raise SystemExit(f'policy: {e}')
    srv = make_server(gate, Config.from_env(insecure_dev, kill_rate), host, port)
    print(f'sf-smartgate {__version__} listening on http://{host}:{srv.server_address[1]}', flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()

import hashlib
import hmac
import json
import threading
import time
import urllib.parse
import urllib.request

import pytest

from sf_smartgate import Gate, Killed
from sf_smartgate.client import RemoteGate, ServerError
from sf_smartgate.gate import Blocked
from sf_smartgate.server import Config, RateLimiter, make_server

AGENT, OPER, SLACK = 'agent-test-token', 'operator-test-token', 'slack-test-secret'


@pytest.fixture
def srv():
    g = Gate()
    cfg = Config(AGENT, OPER, kill_rate=5, slack_signing_secret=SLACK)
    s = make_server(g, cfg, '127.0.0.1', 0)
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    yield g, cfg, f'http://127.0.0.1:{s.server_address[1]}'
    s.shutdown()
    s.server_close()


def call(url, method='GET', body=None, token=None, headers=None):
    h = {'Content-Type': 'application/json', **(headers or {})}
    if token:
        h['Authorization'] = 'Bearer ' + token
    data = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_health_and_metrics(srv):
    g, cfg, url = srv
    assert call(url + '/healthz')[0] == 200
    code, text = call(url + '/metrics')
    assert code == 200 and 'smartgate_decision_latency_ms' in text


def test_auth_required(srv):
    g, cfg, url = srv
    a = {'action_id': 'x', 'agent_id': 'bot', 'action_type': 'read'}
    assert call(url + '/smartgate/evaluate', 'POST', a)[0] == 401
    assert call(url + '/smartgate/evaluate', 'POST', a, 'wrong')[0] == 401
    assert call(url + '/smartgate/evaluate', 'POST', a, AGENT)[0] == 200
    assert call(url + '/smartgate/kill', 'POST', {'action_id': 'x'}, AGENT)[0] == 401


def test_bad_input_is_400(srv):
    g, cfg, url = srv
    assert call(url + '/smartgate/evaluate', 'POST', {'action_id': 'x'}, AGENT)[0] == 400
    assert call(url + '/smartgate/evaluate', 'POST', b'[1,', AGENT)[0] == 400
    assert call(url + '/nope', 'GET')[0] == 404


def test_kill_idempotent_with_request_id(srv):
    g, cfg, url = srv
    c1 = json.loads(call(url + '/smartgate/kill', 'POST', {'action_id': 'k'}, OPER, {'X-Request-ID': 'r1'})[1])
    c2 = json.loads(call(url + '/smartgate/kill', 'POST', {'action_id': 'k'}, OPER, {'X-Request-ID': 'r1'})[1])
    c3 = json.loads(call(url + '/smartgate/kill', 'POST', {'action_id': 'k'}, OPER)[1])
    assert c1 == c2 == {'action_id': 'k', 'status': 'killed', 'first': True, 'seen': False}
    assert c3['first'] is False


def test_rate_limit_on_operator_endpoints(srv):
    g, cfg, url = srv
    codes = [call(url + '/smartgate/kill', 'POST', {'action_id': f'r{i}'}, OPER)[0] for i in range(7)]
    assert codes[:5] == [200] * 5 and codes[5] == 429
    # approvals and releases have their own bucket: an exhausted kill bucket does not block them
    assert call(url + '/smartgate/agents/x/release', 'POST', {}, OPER)[0] == 200
    # failed token checks are limited too
    fails = [call(url + '/smartgate/evaluate', 'POST', {}, 'wrong')[0] for _ in range(25)]
    assert 429 in fails


def test_ip_allowlist(srv):
    g, cfg, url = srv
    from sf_smartgate.server import parse_allowlist
    cfg.kill_allow = parse_allowlist('10.0.0.0/8')
    assert call(url + '/smartgate/kill', 'POST', {'action_id': 'z'}, OPER)[0] == 403
    cfg.kill_allow = parse_allowlist('127.0.0.1')
    assert call(url + '/smartgate/kill', 'POST', {'action_id': 'z'}, OPER)[0] == 200


def test_remote_guard_with_remote_kill(srv):
    g, cfg, url = srv
    agent = RemoteGate(url, agent_token=AGENT, poll_s=0.02)
    oper = RemoteGate(url, operator_token=OPER)
    steps = []
    threading.Timer(0.1, lambda: oper.kill(action_id='rk1', reason='stop')).start()
    with pytest.raises(Killed):
        with agent.guard({'action_id': 'rk1', 'agent_id': 'bot', 'action_type': 'read'}) as h:
            for i in range(100):
                h.checkpoint()
                steps.append(i)
                time.sleep(0.01)
    assert 0 < len(steps) < 100
    assert g.registry.status('rk1')['state'] == 'killed'


def test_remote_prompt_approved_by_operator(srv):
    g, cfg, url = srv
    agent = RemoteGate(url, agent_token=AGENT, poll_s=0.02)
    oper = RemoteGate(url, operator_token=OPER)

    def approve():
        time.sleep(0.1)
        for k, v in list(g.store._d.items()):
            if k.startswith('approval:') and v['state'] == 'pending':
                oper.approve(k.split(':', 1)[1])
    threading.Thread(target=approve).start()
    with agent.guard({'action_id': 'p1', 'agent_id': 'bot', 'action_type': 'api_call', 'cost_usd': 3000}):
        pass
    assert g.registry.status('p1')['state'] == 'completed'


def test_remote_block(srv):
    g, cfg, url = srv
    with pytest.raises(Blocked):
        with RemoteGate(url, agent_token=AGENT).guard({'action_id': 'b1', 'agent_id': 'bot', 'action_type': 'delete', 'reversible': False}):
            pass


def test_fallback_modes_when_server_is_down():
    dead = 'http://127.0.0.1:9'          # discard port: connection refused
    alerts = []
    a = {'action_id': 'f1', 'agent_id': 'bot', 'action_type': 'delete', 'reversible': False}
    allow = RemoteGate(dead, timeout_s=0.5, on_fallback=lambda *x: alerts.append(x))
    assert allow.evaluate(a)['decision'] == 'allow' and alerts
    assert allow.metrics.fallback.value(mode='allow') == 1
    assert RemoteGate(dead, timeout_s=0.5, fallback='block_high').evaluate(a)['decision'] == 'block'
    low = dict(a, action_type='read', reversible=True)
    assert RemoteGate(dead, timeout_s=0.5, fallback='block_high').evaluate(low)['decision'] == 'allow'
    assert RemoteGate(dead, timeout_s=0.5, fallback='block').evaluate(low)['decision'] == 'block'
    with allow.guard(low) as h:     # fallback allow: runs, checkpoint is a no-op
        h.checkpoint()


def sign(body, ts):
    return 'v0=' + hmac.new(SLACK.encode(), b'v0:' + str(ts).encode() + b':' + body, hashlib.sha256).hexdigest()


def test_slack_click_requires_valid_signature_and_kills(srv):
    g, cfg, url = srv
    d = g.evaluate({'action_id': 's1', 'agent_id': 'bot', 'action_type': 'api_call', 'cost_usd': 3000})
    payload = {'user': {'id': 'U1'}, 'actions': [{'action_id': 'smartgate_kill',
                                                  'value': json.dumps({'approval_id': d['approval_id'], 'action_id': 's1'})}]}
    body = urllib.parse.urlencode({'payload': json.dumps(payload)}).encode()
    ts = int(time.time())
    hdr = {'Content-Type': 'application/x-www-form-urlencoded', 'X-Slack-Request-Timestamp': str(ts)}
    assert call(url + '/slack/actions', 'POST', body, headers={**hdr, 'X-Slack-Signature': 'v0=bad'})[0] == 401
    old = ts - 1000
    assert call(url + '/slack/actions', 'POST', body, headers={**hdr, 'X-Slack-Request-Timestamp': str(old), 'X-Slack-Signature': sign(body, old)})[0] == 401
    code, text = call(url + '/slack/actions', 'POST', body, headers={**hdr, 'X-Slack-Signature': sign(body, ts)})
    assert code == 200 and 'Killed by' in text
    assert g.registry.is_killed('s1') and g.approvals.get(d['approval_id'])['state'] == 'rejected'


def test_server_refuses_to_start_without_tokens():
    with pytest.raises(SystemExit):
        make_server(Gate(), Config(), '127.0.0.1', 0)
    with pytest.raises(SystemExit):
        make_server(Gate(), Config(insecure_dev=True), '0.0.0.0', 0)


def test_rate_limiter_refills():
    t = [0.0]
    r = RateLimiter(2, 60, clock=lambda: t[0])
    assert r.allow('a') and r.allow('a') and not r.allow('a')
    t[0] = 30.0
    assert r.allow('a') and not r.allow('a')


def raw_request(url, data: bytes):
    import socket
    host, port = url.split('//')[1].split(':')
    s = socket.create_connection((host, int(port)), timeout=5)
    s.sendall(data)
    out = b''
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    s.close()
    return out.decode('latin-1')


def test_request_id_cannot_be_reused_for_another_action(srv):
    g, cfg, url = srv
    call(url + '/smartgate/kill', 'POST', {'action_id': 'harmless'}, OPER, {'X-Request-ID': 'same'})
    code, text = call(url + '/smartgate/kill', 'POST', {'action_id': 'danger'}, OPER, {'X-Request-ID': 'same'})
    assert code == 409


def test_kill_with_both_ids_is_refused(srv):
    g, cfg, url = srv
    assert call(url + '/smartgate/kill', 'POST', {'action_id': 'a', 'agent_id': 'b'}, OPER)[0] == 400


def test_bad_lengths_and_chunked_bodies_are_refused_and_close(srv):
    g, cfg, url = srv
    r = raw_request(url, b'POST /slack/actions HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n' + b'a' * 1000)
    assert ' 413 ' in r.splitlines()[0] or ' 401 ' in r.splitlines()[0]
    r = raw_request(url, b'POST /smartgate/evaluate HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ' + AGENT.encode() +
                    b'\r\nContent-Length: -1\r\n\r\n')
    assert ' 413 ' in r.splitlines()[0]
    r = raw_request(url, b'POST /smartgate/evaluate HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ' + AGENT.encode() +
                    b'\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nGET /healthz HTTP/1.1\r\nHost: x\r\n\r\n')
    assert ' 411 ' in r.splitlines()[0] and r.count('HTTP/1.') == 1          # no second (smuggled) answer
    big = b'{"x": "' + b'a' * 70000 + b'"}'
    r = raw_request(url, b'POST /smartgate/evaluate HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ' + AGENT.encode() +
                    b'\r\nContent-Length: ' + str(len(big)).encode() + b'\r\n\r\n' + big)
    assert ' 413 ' in r.splitlines()[0] and r.count('HTTP/1.') == 1


def test_allowlist_is_checked_before_the_token(srv):
    g, cfg, url = srv
    from sf_smartgate.server import parse_allowlist
    cfg.kill_allow = parse_allowlist('10.0.0.0/8')
    assert call(url + '/smartgate/kill', 'POST', {'action_id': 'z'}, 'wrong')[0] == 403


def test_server_refuses_to_start_blocked_or_unapproved_actions(srv):
    g, cfg, url = srv
    call(url + '/smartgate/evaluate', 'POST', {'action_id': 'big', 'agent_id': 'bot', 'action_type': 'delete', 'reversible': False}, AGENT)
    assert json.loads(call(url + '/smartgate/actions/big/start', 'POST', {}, AGENT)[1])['started'] is False
    d = json.loads(call(url + '/smartgate/evaluate', 'POST', {'action_id': 'mid', 'agent_id': 'bot', 'action_type': 'api_call', 'cost_usd': 3000}, AGENT)[1])
    assert json.loads(call(url + '/smartgate/actions/mid/start', 'POST', {}, AGENT)[1])['started'] is False
    call(url + f"/smartgate/approvals/{d['approval_id']}/reject", 'POST', {}, OPER)
    assert json.loads(call(url + '/smartgate/actions/mid/start', 'POST', {}, AGENT)[1])['started'] is False
    d2 = json.loads(call(url + '/smartgate/evaluate', 'POST', {'action_id': 'mid2', 'agent_id': 'bot2', 'action_type': 'api_call', 'cost_usd': 3000}, AGENT)[1])
    call(url + f"/smartgate/approvals/{d2['approval_id']}/approve", 'POST', {}, OPER)
    assert json.loads(call(url + '/smartgate/actions/mid2/start', 'POST', {}, AGENT)[1])['started'] is True
    assert call(url + '/smartgate/actions/never/start', 'POST', {}, AGENT)[0] == 200


def test_action_id_of_another_agent_and_bad_target_are_refused(srv):
    g, cfg, url = srv
    a = {'action_id': 'shared', 'agent_id': 'bot2', 'action_type': 'read'}
    assert call(url + '/smartgate/evaluate', 'POST', a, AGENT)[0] == 200
    assert call(url + '/smartgate/evaluate', 'POST', dict(a, agent_id='bot3'), AGENT)[0] == 400
    assert call(url + '/smartgate/evaluate', 'POST', dict(a, action_id='t', target=1.5), AGENT)[0] == 400


def test_ids_with_spaces_and_colons_work_across_the_api(srv):
    g, cfg, url = srv
    agent = RemoteGate(url, agent_token=AGENT)
    with agent.guard({'action_id': 'job:42 x/y', 'agent_id': 'bot', 'action_type': 'read'}):
        pass
    assert g.registry.status('job:42 x/y')['state'] == 'completed'


def test_time_to_override_recorded_for_remote_agents(srv):
    g, cfg, url = srv
    agent = RemoteGate(url, agent_token=AGENT)
    with pytest.raises(Killed):
        with agent.guard({'action_id': 'tto', 'agent_id': 'bot', 'action_type': 'read'}) as h:
            g.kill('tto')
            h.checkpoint()
    assert g.metrics.time_to_override.count == 1


def test_slow_server_is_not_treated_as_down():
    import socket
    ls = socket.socket()
    ls.bind(('127.0.0.1', 0))
    ls.listen(5)                       # accepts, never answers
    url = f'http://127.0.0.1:{ls.getsockname()[1]}'
    d = RemoteGate(url, agent_token=AGENT, timeout_s=0.3).evaluate({'action_id': 's', 'agent_id': 'b', 'action_type': 'read'})
    ls.close()
    assert d['decision'] == 'block' and d['reasons'] == ['GATE-NO-ANSWER']


def test_fallback_actions_still_learn_of_kills_once_the_server_is_back(srv):
    g, cfg, url = srv
    rg = RemoteGate('http://127.0.0.1:9', agent_token=AGENT, timeout_s=0.3)
    with pytest.raises(Killed):
        with rg.guard({'action_id': 'fb1', 'agent_id': 'bot', 'action_type': 'read'}) as h:
            rg.url = url                 # the server is reachable again
            g.kill('fb1', 'stop')        # an operator kills it (a tombstone: the server never saw it)
            h.checkpoint()


def test_slack_replay_malformed_and_late_answers(srv):
    g, cfg, url = srv
    d = g.evaluate({'action_id': 's2', 'agent_id': 'bot', 'action_type': 'api_call', 'cost_usd': 3000})
    g.reject(d['approval_id'], 'someone')
    payload = {'user': {'id': 'U1'}, 'actions': [{'action_id': 'smartgate_approve',
                                                  'value': json.dumps({'approval_id': d['approval_id'], 'action_id': 's2'})}]}
    body = urllib.parse.urlencode({'payload': json.dumps(payload)}).encode()
    ts = int(time.time())
    hdr = {'Content-Type': 'application/x-www-form-urlencoded', 'X-Slack-Request-Timestamp': str(ts), 'X-Slack-Signature': sign(body, ts)}
    code, text = call(url + '/slack/actions', 'POST', body, headers=hdr)
    assert code == 200 and 'Not approved' in text
    assert 'Already handled' in call(url + '/slack/actions', 'POST', body, headers=hdr)[1]
    bad = b'payload=%7B%7D'
    hdr2 = dict(hdr, **{'X-Slack-Signature': sign(bad, ts)})
    assert call(url + '/slack/actions', 'POST', bad, headers=hdr2)[0] == 400


def test_an_action_id_is_evaluated_once(srv):
    g, cfg, url = srv
    call(url + '/smartgate/evaluate', 'POST', {'action_id': 'once', 'agent_id': 'bot', 'action_type': 'delete', 'reversible': False}, AGENT)
    code, _ = call(url + '/smartgate/evaluate', 'POST', {'action_id': 'once', 'agent_id': 'bot', 'action_type': 'read'}, AGENT)
    assert code == 400
    assert json.loads(call(url + '/smartgate/actions/once/start', 'POST', {}, AGENT)[1])['started'] is False


def test_get_with_a_body_is_refused(srv):
    g, cfg, url = srv
    inner = b'POST /smartgate/kill HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ' + OPER.encode() + b'\r\nContent-Length: 22\r\n\r\n{"action_id":"victim"}'
    r = raw_request(url, b'GET /healthz HTTP/1.1\r\nHost: x\r\nContent-Length: ' + str(len(inner)).encode() + b'\r\n\r\n' + inner)
    assert ' 400 ' in r.splitlines()[0] and r.count('HTTP/1.') == 1
    assert g.registry.status('victim') is None


def test_operator_status_reads_do_not_count_as_acknowledgement(srv):
    g, cfg, url = srv
    g.evaluate({'action_id': 'ack1', 'agent_id': 'bot', 'action_type': 'read'})
    g.kill('ack1')
    call(url + '/smartgate/actions/ack1', 'GET', token=OPER)
    assert g.metrics.time_to_override.count == 0
    call(url + '/smartgate/actions/ack1', 'GET', token=AGENT)
    assert g.metrics.time_to_override.count == 1

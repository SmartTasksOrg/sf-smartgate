import json
import os
import subprocess
import sys

import pytest

from sf_smartgate import Gate, Killed
from sf_smartgate.middleware import SmartGateWSGI
from sf_smartgate.rollback import Compensations, atomic_write, staged_write, transaction
from sf_smartgate.slack import SlackNotifier, approval_blocks, verify_signature


def test_atomic_and_staged_write(tmp_path):
    p = tmp_path / 'f.txt'
    atomic_write(str(p), 'v1')
    with pytest.raises(Killed):
        with staged_write(str(p)) as f:
            f.write('half')
            raise Killed('x')
    assert p.read_text() == 'v1'
    assert [x.name for x in tmp_path.iterdir()] == ['f.txt']


def test_transaction_and_compensations():
    log = []
    with pytest.raises(Killed):
        with transaction(lambda: log.append('begin'), lambda: log.append('commit'), lambda: log.append('rollback')):
            raise Killed('x')
    assert log == ['begin', 'rollback']
    undo = []
    with pytest.raises(RuntimeError):
        with Compensations() as c:
            c.add(undo.append, 'refund 1')
            c.add(undo.append, 'refund 2')
            raise RuntimeError('api failed')
    assert undo == ['refund 2', 'refund 1']


def test_slack_payload_and_signature():
    req = {'approval_id': 'ap', 'action_id': 'a1', 'agent_id': 'bot', 'score': 5, 'level': 'medium',
           'reasons': ['GATE-LEVEL-MEDIUM'], 'action_type': 'api_call', 'target': 'refunds'}
    blocks = approval_blocks(req)
    ids = [e['action_id'] for e in blocks[1]['elements']]
    assert ids == ['smartgate_approve', 'smartgate_reject', 'smartgate_kill']
    sent = []
    SlackNotifier(bot_token='xoxb-test', channel='C1', post=lambda *a: sent.append(a)).notify(req)
    assert sent[0][0] == 'https://slack.com/api/chat.postMessage' and json.loads(sent[0][1])['channel'] == 'C1'
    assert not verify_signature('s', 'notanumber', b'', 'v0=x')


def test_wsgi_middleware():
    g = Gate()

    def app(environ, start):
        start('200 OK', [('Content-Type', 'text/plain')])
        return [b'done']

    def describe(env):
        if env['PATH_INFO'] == '/tools/delete':
            return {'agent_id': 'bot', 'action_type': 'delete', 'reversible': False}
        return None
    mw = SmartGateWSGI(app, g, describe)
    seen = {}
    assert mw({'PATH_INFO': '/tools/read'}, lambda s, h: seen.update(s=s)) == [b'done']
    body = mw({'PATH_INFO': '/tools/delete'}, lambda s, h: seen.update(s=s))
    assert seen['s'].startswith('403') and json.loads(body[0])['error'] == 'blocked'


def run_cli(*args):
    return subprocess.run([sys.executable, '-m', 'sf_smartgate.cli', *args], capture_output=True, text=True)


def test_cli(tmp_path):
    assert run_cli('--version').stdout.startswith('SmartGate ')
    r = run_cli('--demo')
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'chain intact' in r.stdout and 'Blocked' in r.stdout
    a = tmp_path / 'a.json'
    a.write_text(json.dumps({'action_id': 'x', 'agent_id': 'b', 'action_type': 'delete', 'reversible': False}))
    assert run_cli('evaluate', str(a)).returncode == 4
    r = run_cli('vectors')
    assert r.returncode == 0 and 'cases passed' in r.stdout
    assert run_cli('policy', 'show').returncode == 0


def test_bench_small():
    from sf_smartgate.bench import run
    rep = run(n=2000, kills=10)
    assert rep['kpi']['override_success_ratio'] == 1.0
    assert rep['traffic']['low'] + rep['traffic']['medium'] + rep['traffic']['high'] == 2000
    assert rep['prompts']['score_below_3'] == rep['prompts']['score_below_3_from_cascade_rule']

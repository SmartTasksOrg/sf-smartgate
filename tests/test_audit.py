import json

from sf_smartgate import AuditLog, verify, verify_file


def test_chain_file_reopen_and_verify(tmp_path):
    p = tmp_path / 'audit.jsonl'
    a = AuditLog(str(p), clock=lambda: 5)
    a.append('decision', action_id='x', score=3)
    a.append('kill', action_id='x', reason='é\n')
    b = AuditLog(str(p), clock=lambda: 6)
    b.append('agent_halt', agent_id='bot')
    ok, idx, msg = verify_file(str(p))
    assert ok and '3 records' in msg
    lines = p.read_text(encoding='utf-8').splitlines()
    rec = json.loads(lines[1])
    rec['reason'] = 'edited'
    lines[1] = json.dumps(rec)
    p.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    ok, idx, _ = verify_file(str(p))
    assert not ok and idx == 1


def test_memory_chain():
    a = AuditLog(clock=lambda: 1)
    for i in range(5):
        a.append('e', n=i)
    assert verify(a.records)[0]
    del a.records[2]
    assert verify(a.records)[1] == 2

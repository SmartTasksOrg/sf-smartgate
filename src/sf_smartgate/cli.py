"""sf-smartgate command line.

    sf-smartgate --version | --demo
    sf-smartgate evaluate action.json [--policy p.json]     decide one action (no server)
    sf-smartgate policy check p.json | policy show           validate / print the default policy
    sf-smartgate serve [--host H] [--port P] [--policy p.json] [--audit audit.jsonl] [--insecure-dev]
    sf-smartgate kill (--action ID | --agent ID) [--reason R] [--url URL]      needs SMARTGATE_OPERATOR_TOKEN
    sf-smartgate approve|reject APPROVAL_ID [--url URL]                        needs SMARTGATE_OPERATOR_TOKEN
    sf-smartgate release AGENT_ID [--url URL]
    sf-smartgate audit verify audit.jsonl
    sf-smartgate vectors [DIR]                                run the conformance vectors (default: bundled)
    sf-smartgate bench [--n 20000] [--json report.json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__


def _url(a):
    return a.url or os.environ.get('SMARTGATE_URL', 'http://127.0.0.1:8711')


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv in (['--version'], ['-V']):
        print(f'SmartGate {__version__}')
        return 0
    if argv == ['--demo']:
        from .demo import main as demo
        return demo()
    p = argparse.ArgumentParser(prog='sf-smartgate', description='Decision friction and a human override for AI agents.')
    p.add_argument('--version', action='version', version=f'SmartGate {__version__}')
    sub = p.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('evaluate', help='decide one action from a JSON file ("-" for stdin)')
    s.add_argument('action')
    s.add_argument('--policy')
    s = sub.add_parser('policy', help='check or show a policy')
    s.add_argument('what', choices=['check', 'show'])
    s.add_argument('path', nargs='?')
    s = sub.add_parser('serve', help='run the SmartGate server')
    s.add_argument('--host', default='127.0.0.1')
    s.add_argument('--port', type=int, default=8711)
    s.add_argument('--policy')
    s.add_argument('--audit', help='append-only audit chain file (JSON lines)')
    s.add_argument('--kill-rate', type=int, default=10, help='operator requests per minute per IP (default 10)')
    s.add_argument('--insecure-dev', action='store_true', help='no tokens; binds 127.0.0.1 only')
    s = sub.add_parser('kill', help='kill an action or halt an agent')
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument('--action')
    g.add_argument('--agent')
    s.add_argument('--reason', default='')
    s.add_argument('--url')
    for name in ('approve', 'reject'):
        s = sub.add_parser(name, help=f'{name} a pending approval')
        s.add_argument('approval_id')
        s.add_argument('--url')
    s = sub.add_parser('release', help='release a halted agent')
    s.add_argument('agent_id')
    s.add_argument('--url')
    s = sub.add_parser('audit', help='verify an audit chain file')
    s.add_argument('what', choices=['verify'])
    s.add_argument('path')
    s = sub.add_parser('vectors', help='run the conformance vectors')
    s.add_argument('dir', nargs='?')
    s = sub.add_parser('bench', help='in-process latency and KPI benchmark')
    s.add_argument('--n', type=int, default=20000)
    s.add_argument('--json')
    a = p.parse_args(argv)

    if a.cmd == 'evaluate':
        from .engine import Engine
        from .policy import Policy
        raw = sys.stdin.read() if a.action == '-' else open(a.action, encoding='utf-8').read()
        d = Engine(Policy.load(a.policy) if a.policy else Policy()).decide(json.loads(raw))
        print(json.dumps(d.to_dict(), indent=2))
        return {'allow': 0, 'prompt': 3, 'block': 4}[d.decision]
    if a.cmd == 'policy':
        from .policy import DEFAULT_POLICY, Policy, PolicyError
        if a.what == 'show':
            print(json.dumps(DEFAULT_POLICY, indent=2))
            return 0
        if not a.path:
            p.error('policy check needs a file')
        try:
            Policy.load(a.path)
        except (PolicyError, ValueError) as e:
            print(f'invalid: {e}')
            return 1
        print('valid')
        return 0
    if a.cmd == 'serve':
        from .server import serve
        serve(a.host, a.port, a.policy, a.audit, a.insecure_dev, a.kill_rate)
        return 0
    if a.cmd in ('kill', 'approve', 'reject', 'release'):
        from .client import RemoteGate, ServerError
        rg = RemoteGate(_url(a), operator_token=os.environ.get('SMARTGATE_OPERATOR_TOKEN'))
        try:
            if a.cmd == 'kill':
                r = rg.kill(action_id=a.action, agent_id=a.agent, reason=a.reason)
            elif a.cmd == 'release':
                r = rg._call('POST', f'/smartgate/agents/{rg._q(a.agent_id)}/release', {}, rg.operator_token)
            else:
                r = getattr(rg, a.cmd)(a.approval_id)
        except ServerError as e:
            print(e, file=sys.stderr)
            return 1
        print(json.dumps(r, indent=2))
        return 0
    if a.cmd == 'audit':
        from .audit import verify_file
        ok, idx, msg = verify_file(a.path)
        print(msg)
        return 0 if ok else 1
    if a.cmd == 'vectors':
        from .conformance import run_dir
        if a.dir:
            total, fails = run_dir(a.dir)
        else:
            from importlib.resources import as_file
            from ._bundled import path
            with as_file(path('conformance')) as d:
                total, fails = run_dir(str(d))
        for f in fails:
            print('FAIL', f)
        print(f'conformance: {total - len(fails)}/{total} cases passed' if not fails else f'conformance: {len(fails)} failure(s)')
        return 1 if fails else 0
    if a.cmd == 'bench':
        from .bench import main as bench
        return bench(a.n, a.json)
    return 2


if __name__ == '__main__':
    raise SystemExit(main())

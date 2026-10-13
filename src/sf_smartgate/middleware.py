"""HTTP middleware: put SmartGate in front of an agent's own HTTP tool server (WSGI or ASGI).

    app = SmartGateWSGI(app, gate, describe=lambda environ: {...action fields...} or None)

``describe`` maps a request to an action descriptor (without action_id: one is made per request) or
returns None for requests that need no gate. A ``block`` answers 403, a ``prompt`` that is not approved
answers 403 too (with the approval id), a killed action 409; otherwise the request goes through.
"""
from __future__ import annotations

import json
import uuid

from .gate import Blocked, Gate
from .registry import Killed


def _refusal(e):
    if isinstance(e, Killed):
        return 409, {'error': 'killed', 'action_id': e.action_id, 'reason': e.reason}
    return 403, {'error': 'blocked', 'why': e.why or e.decision.get('decision'), 'decision': e.decision}


class SmartGateWSGI:
    def __init__(self, app, gate: Gate, describe):
        self.app, self.gate, self.describe = app, gate, describe

    def __call__(self, environ, start_response):
        a = self.describe(environ)
        if a is None:
            return self.app(environ, start_response)
        a = {'action_id': uuid.uuid4().hex, **a}
        try:
            with self.gate.guard(a):
                return list(self.app(environ, start_response))
        except (Blocked, Killed) as e:
            code, body = _refusal(e)
            data = json.dumps(body).encode()
            start_response(f'{code} {"Forbidden" if code == 403 else "Conflict"}',
                           [('Content-Type', 'application/json'), ('Content-Length', str(len(data)))])
            return [data]


class SmartGateASGI:
    def __init__(self, app, gate: Gate, describe):
        self.app, self.gate, self.describe = app, gate, describe

    async def __call__(self, scope, receive, send):
        a = self.describe(scope) if scope.get('type') == 'http' else None
        if a is None:
            return await self.app(scope, receive, send)
        a = {'action_id': uuid.uuid4().hex, **a}
        try:
            return await self.gate.arun(a, self.app, scope, receive, send)
        except (Blocked, Killed) as e:
            code, body = _refusal(e)
            data = json.dumps(body).encode()
            await send({'type': 'http.response.start', 'status': code,
                        'headers': [(b'content-type', b'application/json'), (b'content-length', str(len(data)).encode())]})
            await send({'type': 'http.response.body', 'body': data})

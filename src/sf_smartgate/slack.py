"""Slack: post an approval request with Approve / Reject / Kill buttons, and verify the button clicks.

Sending uses either an incoming-webhook URL or a bot token with ``chat:write`` and a channel id
(``chat.postMessage``). Clicks arrive at ``POST /slack/actions`` on the SmartGate server, which checks
Slack's request signature (``X-Slack-Signature``, ``X-Slack-Request-Timestamp``, your app's signing
secret) before it changes anything. Configure: SMARTGATE_SLACK_WEBHOOK_URL or
SMARTGATE_SLACK_BOT_TOKEN + SMARTGATE_SLACK_CHANNEL, and SMARTGATE_SLACK_SIGNING_SECRET.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
import urllib.request

APPROVE, REJECT, KILL = 'smartgate_approve', 'smartgate_reject', 'smartgate_kill'


def approval_blocks(req: dict) -> list:
    reasons = ', '.join(req.get('reasons') or [])
    target = req.get('target') or '-'
    text = (f"*SmartGate: approval needed* (risk {req['score']}/10, {req['level']})\n"
            f"Agent `{req['agent_id']}` wants to run `{req.get('action_type')}` on `{target}`.\n"
            f"Action `{req['action_id']}` · {reasons}")
    value = json.dumps({'approval_id': req['approval_id'], 'action_id': req['action_id']})
    return [
        {'type': 'section', 'text': {'type': 'mrkdwn', 'text': text}},
        {'type': 'actions', 'elements': [
            {'type': 'button', 'action_id': APPROVE, 'style': 'primary', 'value': value,
             'text': {'type': 'plain_text', 'text': 'Approve'}},
            {'type': 'button', 'action_id': REJECT, 'value': value, 'text': {'type': 'plain_text', 'text': 'Reject'}},
            {'type': 'button', 'action_id': KILL, 'style': 'danger', 'value': value,
             'text': {'type': 'plain_text', 'text': 'Kill'},
             'confirm': {'title': {'type': 'plain_text', 'text': 'Kill this action?'},
                         'text': {'type': 'plain_text', 'text': 'The action is stopped and the kill is logged.'},
                         'confirm': {'type': 'plain_text', 'text': 'Kill'},
                         'deny': {'type': 'plain_text', 'text': 'Cancel'}}},
        ]},
    ]


def _post(url, body: bytes, headers: dict, timeout=5):
    req = urllib.request.Request(url, data=body, headers=headers, method='POST')
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (https URL from configuration)
        return r.status, r.read()


class SlackNotifier:
    def __init__(self, webhook_url=None, bot_token=None, channel=None, post=_post):
        if not webhook_url and not (bot_token and channel):
            raise ValueError('Slack needs a webhook URL, or a bot token and a channel')
        self.webhook_url, self.bot_token, self.channel, self._post = webhook_url, bot_token, channel, post

    def notify(self, req: dict):
        blocks = approval_blocks(req)
        fallback = f"SmartGate approval needed for {req['action_id']} (risk {req['score']}/10)"
        if self.webhook_url:
            body = json.dumps({'text': fallback, 'blocks': blocks}).encode()
            return self._post(self.webhook_url, body, {'Content-Type': 'application/json'})
        body = json.dumps({'channel': self.channel, 'text': fallback, 'blocks': blocks}).encode()
        return self._post('https://slack.com/api/chat.postMessage', body,
                          {'Content-Type': 'application/json; charset=utf-8',
                           'Authorization': 'Bearer ' + self.bot_token})


def verify_signature(signing_secret: str, timestamp: str, body: bytes, signature: str,
                     now: float | None = None, tolerance_s: int = 300) -> bool:
    """Slack's v0 signature: 'v0=' + HMAC-SHA256(secret, 'v0:' + timestamp + ':' + body)."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs((time.time() if now is None else now) - ts) > tolerance_s:
        return False
    base = b'v0:' + str(ts).encode() + b':' + body
    expected = 'v0=' + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or '')


def parse_click(body: bytes):
    """Return (button action_id, approval_id, action_id, slack user id) from an interactivity request."""
    form = urllib.parse.parse_qs(body.decode('utf-8'))
    payload = json.loads(form['payload'][0])
    act = payload['actions'][0]
    value = json.loads(act['value'])
    return act['action_id'], value['approval_id'], value['action_id'], payload.get('user', {}).get('id', '')

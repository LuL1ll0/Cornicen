"""Signed JSON delivery through the shared redirect-free HTTPS transport."""

import hashlib
import hmac
import json
import re
import time

from cornicen.notify.ntfy import post
from cornicen.render import render


MARKER = '\n[truncated]'
FORMATS = frozenset(('json', 'discord', 'slack', 'matrix', 'gotify', 'homeassistant'))


def _clip(text, limit, encoding='utf-8'):
    """Bound encoded text without splitting a code point, including the marker."""
    if len(text.encode(encoding)) <= limit:
        return text
    budget = limit - len(MARKER.encode(encoding))
    return text.encode(encoding)[:budget].decode(encoding, errors='ignore') + MARKER


def _cve_ids(n):
    if 'items' in n.body:
        return sorted({record for item in n.body['items']
                       for record in _cve_ids_from_item(item)})
    return [n.record_id] if re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,19}', n.record_id) else []


def _cve_ids_from_item(item):
    # Durable digest members have the same Notification representation.
    from cornicen.model import Notification
    return _cve_ids(Notification(**item))


def payload(n, shape):
    title, body, priority, _ = render(n)
    title = _clip(title, 256)
    # Conservative local budgets for services without a field-specific limit.
    body = _clip(body, 8000)
    text = title + '\n' + body
    if shape == 'discord':
        return {'content': _clip(re.sub(r'([\\`*_{}\[\]()<>~|])', r'\\\1', text), 4000, 'utf-16-le'), 'allowed_mentions': {'parse': []}}
    if shape == 'slack':
        return {'text': _clip(text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'), 4000)}
    if shape == 'matrix':
        return {'msgtype': 'm.text', 'body': text, 'm.mentions': {}}
    if shape == 'gotify':
        return {'title': title, 'message': body, 'priority': priority,
                'extras': {'client::display': {'contentType': 'text/plain'}}}
    return {'title': title, 'priority': priority, 'body': body, 'cve_ids': _cve_ids(n)}


class WebhookNotifier:
    def __init__(self, http_post, url, secret, shape='json', *, clock=time.time):
        if shape not in FORMATS:
            raise ValueError('Invalid webhook format')
        self.http_post, self.url, self.secret = http_post, url, secret
        self.shape, self.clock = shape, clock

    def send(self, n):
        try:
            # Same body as ntfy delivers: stored notifications carry no credentials.
            body = json.dumps(payload(n, self.shape), ensure_ascii=False,
                              separators=(',', ':')).encode('utf-8')
            timestamp = str(int(self.clock()))
            signature = hmac.new(self.secret.reveal().encode('utf-8'),
                                 timestamp.encode('ascii') + b'.' + body,
                                 hashlib.sha256).hexdigest()
            headers = {'Content-Type': 'application/json',
                       'X-Cornicen-Timestamp': timestamp,
                       'X-Cornicen-Signature': 'sha256=' + signature}
            status = self.http_post(self.url.reveal(), body, headers)
            return 200 <= status < 300
        except Exception:
            # Transport exceptions may contain either credential; never emit them.
            return False

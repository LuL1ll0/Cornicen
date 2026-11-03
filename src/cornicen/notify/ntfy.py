"""ntfy delivery with no redirect forwarding or diagnostic secret output."""

from email.header import Header
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cornicen.render import render


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def post(url, body, headers):
    # urllib's default redirect handler can forward Authorization. Disable all
    # redirects, including same-host redirects, for this authenticated channel.
    headers = dict(headers)
    if 'Title' in headers:
        title = ' '.join(headers['Title'].splitlines())
        headers['Title'] = Header(title, 'utf-8', maxlinelen=1000000).encode()
    request = Request(url, data=body, headers=headers, method='POST')
    try:
        with build_opener(_NoRedirect()).open(request, timeout=60) as response:
            return response.status
    except HTTPError as error:
        status = error.code
        error.close()
        return status


class NtfyNotifier:
    def __init__(self, http_post, url, topic, token):
        self.http_post = http_post
        self.url = url.rstrip('/') + '/' + quote(topic, safe='')
        self.token = token

    def send(self, n):
        try:
            title, text, priority, tags = render(n)
            headers = {'Title': title, 'Priority': str(priority), 'Tags': ','.join(tags),
                       'X-Cornicen-Event': n.key,
                       'Content-Type': 'text/plain; charset=utf-8'}
            if self.token is not None:
                headers['Authorization'] = 'Bearer ' + self.token.reveal()
            status = self.http_post(self.url, text.encode('utf-8'), headers)
            return 200 <= status < 300
        except Exception:
            # Even an HTTP implementation's exception can contain credentials.
            return False

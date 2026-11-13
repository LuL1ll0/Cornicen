"""A payload-free, opt-in completion ping with host-bound redirects."""

from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class SameHostRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            original, target = urlsplit(req.full_url), urlsplit(newurl)
            if (target.scheme not in {'http', 'https'}
                    or target.hostname != original.hostname
                    or (original.scheme == 'https' and target.scheme != 'https')):
                return None
        except ValueError:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def ping(url):
    """GET the configured URL without reading a response body; raises on failure."""
    request = Request(url, headers={'User-Agent': 'Cornicen'}, method='GET')
    with build_opener(SameHostRedirect()).open(request, timeout=10):
        pass

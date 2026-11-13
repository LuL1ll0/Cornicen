"""Final word boundary for container-log diagnostics."""

import builtins
import re
import string
import unicodedata

from cornicen.vocabulary import WORDS


PUNCTUATION = '.,;:!?()[]{}<>"\''
MARKER = '[redacted]'
RECORD_ID_PREFIXES = ('Dead-letter records:', 'Missing stored record:',
                      'Declared record missing or invalid:')
ISO = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}(?:T[0-9]{2}:[0-9]{2}(?::[0-9]{2})?(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})?)?')
BUILTIN_EXCEPTIONS = frozenset(name.casefold() for name, value in vars(builtins).items()
                               if isinstance(value, type) and issubclass(value, BaseException))


def _strip(text):
    return ''.join(c for c in str(text) if not unicodedata.category(c).startswith('C'))


class _Inventory(frozenset):
    pass


def prepare_inventory(watches):
    try:
        return _inventory(watches)
    except Exception:
        return None


def _inventory(watches):
    if isinstance(watches, _Inventory):
        return watches
    if watches is None:
        raise ValueError('Inventory unavailable')
    words = set()
    for watch in watches:
        values = [watch.id, watch.name, watch.version, *watch.product_only]
        values.extend(value for value in (watch.latest_release, watch.release_tag_prefix) if value)
        values.extend(part for identity in watch.match for part in identity)
        for value in values:
            value = unicodedata.normalize('NFKC', _strip(value)).casefold()
            if not value:
                continue
            words.add(value)
            words.update(re.findall(r'[^\W_]+', value))
    return _Inventory(words)


def _allowed(token, inventory):
    if token == MARKER:
        return True
    if all(c in string.punctuation for c in token):
        return len(token) == 1
    leading = len(token) - len(token.lstrip(PUNCTUATION))
    trailing = len(token) - len(token.rstrip(PUNCTUATION))
    if leading > 1 or trailing > 1:
        return False
    core = token.strip(PUNCTUATION)
    if re.fullmatch(r'[0-9]+', core) or ISO.fullmatch(core):
        return True
    return (core.isascii() and core.casefold() in (WORDS | BUILTIN_EXCEPTIONS)
            and core.casefold() not in inventory
            and not (len(core) >= 4 and any(core.casefold() in value for value in inventory)))


def public_text(text, inventory=()) -> str:
    try:
        words = _inventory(inventory)
        result = []
        text = _strip(text)
        for prefix in RECORD_ID_PREFIXES:
            text = re.sub(re.escape(prefix) + r'.*', prefix + ' ' + MARKER, text)
        for token in text.split():
            token = token if _allowed(token, words) else MARKER
            if token != MARKER or not result or result[-1] != MARKER:
                result.append(token)
        return ' '.join(result)
    except Exception:
        return MARKER


def public_token(token, inventory=()) -> str | None:
    try:
        tokens = _strip(token).split()
        if len(tokens) == 1 and _allowed(tokens[0], _inventory(inventory)):
            return tokens[0]
        return None
    except Exception:
        return None


def epss_crossing_text(record_id):
    """Fixed crossing notice with a validated public record identifier."""
    if not isinstance(record_id, str) or not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,19}', record_id):
        record_id = MARKER
    return 'EPSS threshold crossed: ' + record_id

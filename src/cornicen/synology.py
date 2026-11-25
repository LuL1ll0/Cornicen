"""Parse and map Synology RSS without I/O or version inference."""

from hashlib import sha256
import json
import re
import unicodedata
from xml.etree import ElementTree

from cornicen import feeddates, feedvalidate
from cornicen.diagnostics import FixedDiagnostic
from cornicen.public_text import UNRECOGNISED_SUBJECT, UNRECOGNISED_TEMPLATE
from cornicen.synology_products import SYNOLOGY_PRODUCTS


MAPPING_VERSION = 'synology-templates-1'
_PRODUCT_NAMES = {
    name.casefold(): product
    for alias, (_, product) in SYNOLOGY_PRODUCTS.items()
    for name in (alias, product)
}

_GUID = re.compile(r'https://www\.synology\.com/[a-z]{2}-[a-z]{2}/(?:support/)?security/([A-Za-z0-9_.-]{1,120})')
_CVE = r'CVE-[0-9]{4}-[0-9]{4,}'
_CVE_TOKEN = re.compile(rf'\b{_CVE}\b')
_LEAD = re.compile(
    rf'(?:A vulnerability|Multiple vulnerabilities|{_CVE}(?:(?:, |, and | and ){_CVE})*) allows? '
)
_BOUNDARY = re.compile(r'\.(?= [A-Z]|$)')
_AMBIGUOUS = re.compile(r'\.(?![0-9])')
_NONE = re.compile(r"None of Synology's products are affected by(?= |$)")
_UPDATE = 'Synology has released a security update for '
_PRODUCT_SEPARATOR = re.compile(r', and |, | and | or ')
_PACKAGES = ' via susceptible versions of the following packages in '
_SINGLE = ' via a susceptible version of '
_NEGATION = re.compile(
    r"\b(?:not|cannot|can't|never|no longer|unable to) (?:be |been )?"
    r"(?:exploit|affect|vulnerab|impact|susceptib)", re.IGNORECASE,
)


def parse_feed(body):
    """Return raw item dictionaries and channel observations, or raise ValueError."""
    if len(body) > 8 * 1024**2 or b'\0' in body:
        raise ValueError(FixedDiagnostic('invalid Synology RSS envelope'))
    try:
        xml = body.decode('utf-8', errors='strict')
        root = ElementTree.fromstring(feedvalidate.reject_xml_entities(xml))
    except (UnicodeError, ElementTree.ParseError):
        raise ValueError(FixedDiagnostic('invalid Synology RSS envelope')) from None
    channels = root.findall('channel')
    if root.tag != 'rss' or len(channels) != 1:
        raise ValueError(FixedDiagnostic('invalid Synology RSS envelope'))
    channel = channels[0]
    items = channel.findall('item')
    if not 1 <= len(items) <= 5000:
        raise ValueError(FixedDiagnostic('invalid Synology RSS envelope'))
    keys = ('guid', 'link', 'title', 'pubDate', 'description')
    return ([{key: item.findtext(key) for key in keys if item.find(key) is not None}
             for item in items], {'lastBuildDate': channel.findtext('lastBuildDate')})


def _captures(template, names):
    recognised = {}
    unknown = 0
    for name in names:
        product = _PRODUCT_NAMES.get(name.strip().casefold())
        if product is not None:
            recognised[product] = None
        else:
            unknown += 1
    return list(recognised), template, {UNRECOGNISED_SUBJECT: unknown} if unknown else {}


def _exploit_subject(sentence, phrase):
    lead = _LEAD.match(sentence)
    if lead:
        action, sep, subject = sentence[lead.end():].partition(phrase)
        actor, to, effect = action.partition(' to ')
        if (sep and to and actor.strip() and effect.strip() and subject.strip()
                and not (phrase == _SINGLE and _NEGATION.search(action))):
            return subject.strip()
    return None


def _package_names(description):
    lines = description.lstrip().splitlines()
    previous = ''
    for index, raw in enumerate(lines):
        line = ' '.join(raw.split())
        if not line:
            continue
        parts = _BOUNDARY.split(line)
        at_boundary = not previous or previous.endswith('.') or len(parts) > 1
        previous = line
        if not at_boundary or not line.endswith(':'):
            continue
        sentence = parts[-1].lstrip()
        if not _exploit_subject(sentence[:-1], _PACKAGES):
            continue
        start = index + 1
        # The feed can separate the lead-in and the list with a spacer.
        if start < len(lines) and not lines[start].strip():
            start += 1
        names = []
        for raw_name in lines[start:]:
            name = raw_name.strip()
            if not name:
                break
            names.append(name)
        return names
    return None


def _statement_text(sentence):
    match = _NONE.match(sentence)
    return sentence[match.end():].strip() if match else ''


def _affirmative_products(description, sentences):
    for sentence in sentences:
        if sentence.startswith(_UPDATE):
            name, sep, remainder = sentence[len(_UPDATE):].removeprefix('the ').partition(' to address')
            if (name and sep and remainder.startswith(' ') and remainder.strip()
                    and not _AMBIGUOUS.search(name) and not _NEGATION.search(name)):
                return _captures('S-UPD', _PRODUCT_SEPARATOR.split(name))
    names = _package_names(description)
    if names is not None:
        return _captures('S-PKG', names)
    for sentence in sentences:
        name = _exploit_subject(sentence, _SINGLE)
        # S-ONE also disallows decimal dots. A terminal "etc." loses its dot at the split.
        if name and not _AMBIGUOUS.search(name) and not re.search(r'\.[0-9]|\betc$', name):
            return _captures('S-ONE', _PRODUCT_SEPARATOR.split(name))
    return [], None, {UNRECOGNISED_TEMPLATE: 1}


def analyse_description(description):
    """Return products, affirmative template, diagnostics and optional statement scope."""
    sentences = [part.lstrip() for part in _BOUNDARY.split(' '.join(description.split()))]
    statements = [text for sentence in sentences if (text := _statement_text(sentence))]
    statement_cves = list(dict.fromkeys(
        cve for sentence in statements for cve in _CVE_TOKEN.findall(sentence)
    )) if statements else None
    names, template, diagnostics = _affirmative_products(description, sentences)
    if template is None and statements:
        template, diagnostics = 'S-NONE', {}
    return names, template, diagnostics, statement_cves


def products(title, description):
    """Project the description analysis to products, template and diagnostics."""
    names, template, diagnostics, _ = analyse_description(description)
    return names, template, diagnostics


def _identity(item):
    guid = item.get('guid', item.get('link'))
    match = _GUID.fullmatch(guid) if isinstance(guid, str) else None
    return guid, match[1] if match else None


def _duplicate_key(item):
    try:
        published = feeddates.rfc822(item.get('pubDate'))
    except ValueError:
        return item
    return dict(item, pubDate=published)


def normalise_items(items, diagnostics):
    """Map a feed after distinguishing conflicting raw items from mapping failures."""
    identities = [_identity(item)[1] for item in items]
    first, conflicts = {}, set()
    for item, identity in zip(items, identities):
        if identity is not None:
            key = _duplicate_key(item)
            if first.setdefault(identity, key) != key:
                conflicts.add(identity)
    # Preserve distinct digests for the store's conflict index without carrying
    # conflicting raw text into the staged members.
    return [dict(id=identity, raw_digest=sha256(json.dumps(item, sort_keys=True).encode()).hexdigest())
            if identity in conflicts else normalise(item, diagnostics=diagnostics)
            for item, identity in zip(items, identities)]


def normalise(item, *, diagnostics=None):
    """Map one raw item, keeping an identifiable malformed member for quarantine."""
    guid, identity = _identity(item)
    if identity is None:
        return dict(id=None, guid=guid, mapping_error='invalid Synology guid')
    for key in ('link', 'title', 'pubDate', 'description'):
        value = item.get(key)
        if not isinstance(value, str) or not value.strip():
            return dict(id=identity, mapping_error='missing Synology item text')
    title, description = item['title'], item['description']
    if len(description.encode('utf-8')) > 64 * 1024:
        return dict(id=identity, mapping_error='Synology description too large')
    if len(title) > 300 or any(unicodedata.category(c) in ('Cc', 'Cf') for c in title):
        return dict(id=identity, mapping_error='invalid Synology title')
    try:
        url = feedvalidate.display_url(item['link'])
        published = feeddates.rfc822(item['pubDate']).utc()
    except (ValueError, OverflowError):
        return dict(id=identity, mapping_error='invalid Synology URL or publication date')

    names, _, template_counts, statement_cves = analyse_description(description)
    if diagnostics is not None:
        diagnostics.update(template_counts)
    product_rows = [dict(id=f'synology:{name.lower()}', name=f'synology:{name.lower()}')
                    for name in names]
    member = dict(id=identity, guid=guid, url=url, title=title, published=published,
                  details=description, mapping_version=MAPPING_VERSION,
                  cves=list(dict.fromkeys(_CVE_TOKEN.findall(title + '\n' + description))),
                  products=product_rows,
                  evidence=[dict(product_id=p['id'], scheme='opaque', status='under_investigation')
                            for p in product_rows])
    if statement_cves is not None:
        member['vendor_statement'] = 'none_affected'
        member['statement_cves'] = statement_cves
    return member

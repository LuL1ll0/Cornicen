# script-purpose: Validate shared feed boundaries and normalize advisory evidence.
# script-class: pipeline-tool
# script-trigger: Adapter resource and member ingestion.
# script-tests: tests/test_f1.py, tests/test_f3a.py, tests/test_f3b.py, tests/test_task1_a.py, tests/test_task1_b1.py, tests/test_task1_b2.py
"""Read raw feed objects; return validated records without writing files.

Library API with no process exit codes; invalid inputs raise ValueError.
"""
from dataclasses import dataclass, field
from hashlib import sha256
import json
import re
import unicodedata
from urllib.parse import unquote, urlsplit

from cornicen import feeddates
from cornicen.diagnostics import FixedDiagnostic
from cornicen.versions import Scheme


def _error(message):
    return ValueError(FixedDiagnostic(message))


def source_id(value):
    if (not isinstance(value, str) or not value.strip() or '|' in value or
            any(unicodedata.category(c) == 'Cc' for c in value)):
        raise _error('invalid advisory source ID')
    return value


def display_url(value):
    try:
        parsed = urlsplit(value) if isinstance(value, str) else None
        if parsed is None or parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise ValueError
        if any(c.isspace() or unicodedata.category(c) == 'Cc' for c in value):
            raise ValueError
        parsed.port
    except ValueError:
        raise _error('invalid advisory display URL') from None
    return value


def safe_path(value):
    if not isinstance(value, str):
        raise _error('unsafe resource path')
    try:
        decoded = unquote(value, errors='strict')
    except UnicodeError:
        raise _error('unsafe resource path') from None
    if (not decoded or '\\' in decoded or ':' in decoded or
            any(unicodedata.category(c) == 'Cc' for c in decoded) or
            any(part in ('', '.', '..') for part in decoded.split('/'))):
        raise _error('unsafe resource path')
    return decoded


def reject_xml_entities(value):
    if isinstance(value, bytes):
        try:
            value = value.decode('utf-8', errors='strict')
        except UnicodeError:
            raise _error('invalid UTF-8 XML') from None
    if not isinstance(value, str) or re.search(r'<!\s*(?:DOCTYPE|ENTITY)\b', value, re.I):
        raise _error('XML DTD and entity declarations are forbidden')
    return value


def decode_json(body):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise _error('duplicate JSON key')
            result[key] = value
        return result

    def constant(value):
        raise _error('non-finite JSON number')

    try:
        if isinstance(body, bytes):
            body = body.decode('utf-8', errors='strict')
        if not isinstance(body, str):
            raise ValueError
        # Reject unpaired surrogates even on the string-only fixture path.
        body.encode('utf-8', errors='strict')
        return json.loads(body, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise _error('invalid strict UTF-8 JSON') from None


_VALIDATED = object()


@dataclass(frozen=True, init=False)
class ValidatedAdvisory:
    """Only validate_advisory constructs this boundary type."""
    data: dict

    def __init__(self, data, *, _token=None):
        if _token is not _VALIDATED:
            raise TypeError('ValidatedAdvisory requires advisory validation')
        object.__setattr__(self, 'data', data)


@dataclass
class AdapterResult:
    """One-shot record stream; classification finalizes when fully consumed."""
    records: object
    classification: str = 'COMPLETE'
    quarantine: list = field(default_factory=list)
    quarantine_reasons: dict = field(default_factory=dict)

    def checked_records(self):
        for record in self.records:
            if not isinstance(record, ValidatedAdvisory):
                raise TypeError('AdapterResult requires ValidatedAdvisory records')
            yield record


def _string_list(value):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _advisory_text(value, cap):
    if isinstance(value, str) and (len(value) > cap or any(
            unicodedata.category(c) in ('Cc', 'Cf') for c in value)):
        raise _error('unsafe advisory text')


def _validate_evidence(evidence_rows, products):
    for evidence in evidence_rows:
        if not isinstance(evidence, dict):
            raise _error('invalid advisory evidence')
        try:
            Scheme(evidence.get('scheme'))
        except (ValueError, TypeError):
            raise _error('unknown version scheme') from None
        for field in ('release', 'platform', 'fix', 'first_fixed'):
            if evidence.get(field) is not None and not isinstance(evidence[field], str):
                raise _error('invalid advisory evidence field type')
        for field in ('fix', 'first_fixed'):
            _advisory_text(evidence.get(field), 200)
        if not isinstance(evidence.get('product_id'), str) or evidence['product_id'] not in products:
            raise _error('unresolved advisory product reference')
        if evidence.get('status') not in ('known_affected', 'known_not_affected', 'under_investigation', 'first_fixed'):
            raise _error('invalid advisory evidence status')
        if 'range' in evidence and not isinstance(evidence['range'], dict):
            raise _error('invalid advisory range')
        if any(not isinstance(bound, str) for bound in evidence.get('range', {}).values()):
            raise _error('invalid advisory range bound')


def validate_advisory(raw, *, source, observed_at, input_path='', date_fields=None):
    if not isinstance(raw, dict):
        raise _error('advisory must be an object')
    if 'mapping_error' in raw:
        raise _error('advisory mapping failed')
    if 'retraction' in raw and raw['retraction'] != 'administrative':
        raise _error('invalid advisory retraction')
    identity = source_id(raw.get('id'))
    _advisory_text(raw.get('url'), 2000)
    _advisory_text(raw.get('title'), 300)
    url = display_url(raw.get('url'))
    if not isinstance(raw.get('title'), str) or not raw['title'].strip():
        raise _error('advisory requires a title')
    dates = {}
    # Source-specific adapters supply their field map; fixtures use these fields.
    date_fields = date_fields if date_fields is not None else {
        'published': (True, 'rfc3339'), 'updated': (True, 'rfc3339'),
        'withdrawn': (False, 'rfc3339')}
    for name, (required, grammar) in date_fields.items():
        value = raw.get(name)
        if value is None:
            if required:
                raise _error('required advisory date missing')
            dates[name] = None
        else:
            parser = {'rfc3339': feeddates.rfc3339, 'rfc822': feeddates.rfc822}.get(grammar)
            if parser is None:
                raise _error('unknown advisory date grammar')
            dates[name] = parser(value).raw
    for name in ('products', 'evidence', 'cves'):
        if not isinstance(raw.get(name), list):
            raise _error('advisory requires product, evidence and CVE arrays')
    products = {}
    for product in raw['products']:
        if not isinstance(product, dict) or not isinstance(product.get('name'), str):
            raise _error('invalid advisory product')
        if product.get('version') is not None and not isinstance(product['version'], str):
            raise _error('invalid advisory product version')
        key = source_id(product.get('id'))
        if key in products:
            raise _error('duplicate advisory product ID')
        products[key] = product
    for field in ('product_groups', 'remediations', 'associations', 'identifiers'):
        if not isinstance(raw.get(field, []), list):
            raise _error('invalid advisory array')
    groups = {}
    for group in raw.get('product_groups', []):
        if not isinstance(group, dict) or not _string_list(group.get('product_ids')):
            raise _error('invalid advisory product group')
        key = source_id(group.get('id'))
        if key in groups or any(p not in products for p in group['product_ids']):
            raise _error('unresolved advisory product group')
        groups[key] = group
    _validate_evidence(raw['evidence'], products)
    for remediation in raw.get('remediations', []):
        if (not isinstance(remediation, dict) or
                not _string_list(remediation.get('product_ids', [])) or
                not _string_list(remediation.get('group_ids', [])) or
                (remediation.get('version') is not None and not isinstance(remediation['version'], str)) or
                any(g not in groups for g in remediation.get('group_ids', [])) or
                any(p not in products for p in remediation.get('product_ids', []))):
            raise _error('unresolved advisory remediation reference')
        _advisory_text(remediation.get('version'), 200)
    if any(not isinstance(cve, str) or not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', cve) for cve in raw['cves']):
        raise _error('invalid advisory CVE relationship')
    for association in raw.get('associations', []):
        if (not isinstance(association, dict) or not isinstance(association.get('product_id'), str) or association['product_id'] not in products or
                association.get('cve') not in raw['cves']):
            raise _error('unresolved advisory association')
    cves = [dict(value=cve, field_path=f'cves[{n}]') for n, cve in enumerate(raw['cves'])]
    for n, identifier in enumerate(raw.get('identifiers', [])):
        if isinstance(identifier, dict) and identifier.get('type') == 'CVE':
            value = identifier.get('value')
            if not isinstance(value, str) or not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', value):
                raise _error('invalid advisory CVE relationship')
            if value not in {c['value'] for c in cves}:
                cves.append(dict(value=value, field_path=f'identifiers[{n}].value'))
    facets = raw.get('facets', [])
    if not isinstance(facets, list) or any(not isinstance(f, dict) for f in facets):
        raise _error('invalid advisory facets')
    normalized_facets = []
    record_cves = {c['value'] for c in cves}
    for facet in facets:
        facet = dict(facet)
        values = []
        for key in ('cve', 'cves'):
            if key not in facet:
                continue
            items = [facet[key]] if isinstance(facet[key], str) else facet[key]
            if (not _string_list(items) or any(
                    not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', c) or c not in record_cves for c in items)):
                raise _error('invalid facet CVE relationship')
            values.extend(c for c in items if c not in values)
        facet.pop('cve', None)
        facet['cves'] = values
        if 'title' in facet and not isinstance(facet['title'], str):
            raise _error('invalid facet title')
        _advisory_text(facet.get('title'), 300)
        ids = facet.get('ids', [])
        if not isinstance(ids, list) or any(not isinstance(i, dict) or
                any(not isinstance(k, str) or not isinstance(v, str) for k, v in i.items()) for i in ids):
            raise _error('invalid facet ids')
        entries = facet.get('products', [])
        if not isinstance(entries, list):
            raise _error('invalid facet products')
        for product in entries:
            name = product.get('name') if isinstance(product, dict) else product
            if not isinstance(name, str) or not any(p['name'] == name for p in products.values()):
                raise _error('unresolved facet product reference')
            if isinstance(product, dict) and 'id' in product and (
                    not isinstance(product['id'], str) or product['id'] not in products or
                    products[product['id']]['name'] != name):
                raise _error('unresolved facet product reference')
        evidence = facet.get('evidence', [])
        if not isinstance(evidence, list):
            raise _error('invalid facet evidence')
        try:
            _validate_evidence(evidence, products)
        except ValueError as error:
            raise _error('invalid facet evidence: ' + str(error)) from None
        associations = facet.get('associations', [])
        if not isinstance(associations, list) or any(not isinstance(a, dict) or
                not isinstance(a.get('product_id'), str) or a['product_id'] not in products or
                not isinstance(a.get('cve'), str) or a['cve'] not in record_cves for a in associations):
            raise _error('unresolved facet association')
        normalized_facets.append(facet)
    encoded = json.dumps(raw, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    data = dict(source=source, source_id=identity, title=raw['title'], url=url,
                published=dates.get('published'), updated=dates.get('updated'),
                observed_at=observed_at, digest=sha256(encoded.encode('utf-8')).hexdigest(),
                facets=normalized_facets,
                cves=cves,
                provenance=dict(input_path=input_path, field_path='$', alias_map_version=None),
                products=raw['products'], evidence=raw['evidence'], **{'dates': dates})
    data['withdrawn'] = dates.get('withdrawn')
    if 'retraction' in raw:
        data['retraction'] = raw['retraction']
    for key in ('associations', 'product_groups', 'remediations'):
        data[key] = raw.get(key, [])
    return ValidatedAdvisory(data, _token=_VALIDATED)


def validate_members(members, *, source, observed_at, input_path='', date_fields=None):
    result = AdapterResult(None)

    def stream():
        for raw in members:
            try:
                record = validate_advisory(raw, source=source, observed_at=observed_at,
                                          input_path=input_path, date_fields=date_fields)
            except (ValueError, TypeError, KeyError) as error:
                result.classification = 'PARTIAL'
                try:
                    key = source_id(raw.get('id') if isinstance(raw, dict) else None)
                    from cornicen.adapterstore import safe_detail
                    reason = safe_detail(error)
                except ValueError:
                    key = '@invalid:' + sha256(json.dumps(raw, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
                    reason = 'invalid id'
                result.quarantine.append(key)
                result.quarantine_reasons[key] = reason
            else:
                yield record
    result.records = stream()
    return result


def validate_resource(resource, *, source, observed_at, prior_count=0, date_fields=None):
    """Classify raw transport/envelope; callers must exhaust records before use."""
    empty = lambda state: AdapterResult(iter(()), state)
    if resource.get('invalid_envelope') or resource['status'] < 200 or resource['status'] >= 300:
        return empty('FAILED')
    if not resource.get('transfer_complete', True) or resource.get('integrity', 'intact') == 'pending':
        return empty('PARTIAL')
    if resource.get('integrity', 'intact') != 'intact':
        return empty('FAILED')
    try:
        path = safe_path(resource['path'])
        body = decode_json(resource['body'])
    except ValueError:
        return empty('FAILED')
    envelope = body if isinstance(body, dict) else {}
    members = envelope.get('advisories') if isinstance(body, dict) else body
    if not isinstance(members, list) or 'error' in envelope or 'errors' in envelope:
        return empty('FAILED')
    result = validate_members(members, source=source, observed_at=observed_at,
                              input_path=path, date_fields=date_fields)
    if (len(members) * 5 < prior_count * 4  or
            envelope.get('pagination_stable', True) is not True or
            envelope.get('expected_count', len(members)) != len(members) or
            envelope.get('coverage_complete', True) is not True):
        result.classification = 'PARTIAL'
    return result

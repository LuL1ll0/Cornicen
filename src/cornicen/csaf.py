# script-purpose: Normalize CSAF documents into scoped advisory facets without I/O.
# script-class: pipeline-tool
# script-trigger: CSAF callers and offline tests.
# script-tests: tests/test_task2_a.py, tests/test_task3_a.py
"""Read decoded CSAF objects; return product indexes or normalized advisory members.

Pure library API: no files, clock, network, writes or process exit codes.
Invalid publisher content returns a mapping_error dictionary.
"""
import re
from dataclasses import dataclass

from cornicen.identity import normalise_identity

from cornicen.feeddates import rfc3339


@dataclass(frozen=True)
class NormalisationPolicy:
    family_names: bool = False
    service_pack_versions: bool = False
    relationships: bool = False


MICROSOFT = NormalisationPolicy()
CISCO = NormalisationPolicy(True, True, True)


def _object(value):
    if not isinstance(value, dict):
        raise ValueError('invalid CSAF object')
    return value


def _array(value):
    if not isinstance(value, list):
        raise ValueError('invalid CSAF array')
    return value


def _text(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('invalid CSAF text')
    return value


def _references(values, products):
    values = _array(values)
    if any(not isinstance(p, str) or p not in products for p in values):
        raise ValueError('dangling product reference')
    return values


def _index(document, policy):
    tree = _object(_object(document).get('product_tree', {}))
    products, branch_products, scopes = {}, set(), {}

    def add(product, ancestors=None, category=None, name=None):
        product = _object(product)
        pid = _text(product.get('product_id'))
        _text(product.get('name'))
        if pid in products:
            raise ValueError('duplicate product ID')
        ancestors = ancestors or {}
        vendor = ancestors.get('vendor')
        product_name = ancestors.get('product_name')
        if policy.family_names and not product_name:
            product_name = ancestors.get('product_family')
        if vendor and ':' in vendor:
            raise ValueError('invalid vendor name')
        entry = dict(id=pid, name=f'{vendor}:{product_name}' if vendor and product_name else f'csaf-unresolved:{pid}')
        if category == 'product_version' or (policy.service_pack_versions and category == 'service_pack'):
            entry['version'] = _text(name)
        if category == 'product_version_range':
            entry['range'] = {'csaf': _text(name)}
        products[pid] = entry
        if vendor and product_name:
            branch_products.add(pid)
        return pid

    def branches(items, ancestors):
        for branch in _array(items):
            branch = _object(branch)
            category, name = _text(branch.get('category')), _text(branch.get('name'))
            if category == 'vendor' and ':' in name:
                raise ValueError('invalid vendor name')
            context = ancestors | {category: name}
            if 'product' in branch:
                add(branch['product'], context, category, name)
            branches(branch.get('branches', []), context)

    branches(tree.get('branches', []), {})
    for product in _array(tree.get('full_product_names', [])):
        add(product)
    relationships, categories = {}, {}
    for relationship in _array(tree.get('relationships', [])):
        relationship = _object(relationship)
        pid = add(relationship.get('full_product_name'))
        if policy.relationships:
            categories[pid] = _text(relationship.get('category'))
        relationships[pid] = [relationship.get('product_reference'), relationship.get('relates_to_product_reference')]
    # Validate all edges, including relationships not asserted by a vulnerability.
    visiting, visited = set(), set()

    def resolve(pid):
        if pid in visiting:
            raise ValueError('relationship cycle')
        if pid in visited:
            return
        visiting.add(pid)
        for ref in _references(relationships.get(pid, []), products):
            resolve(ref)
        visiting.remove(pid)
        visited.add(pid)

    for pid in products:
        resolve(pid)
    for group in _array(tree.get('product_groups', [])):
        _references(_object(group).get('product_ids'), products)
    if policy.relationships:
        resolved = {}

        def component_scope(pid):
            if pid in resolved:
                return resolved[pid]
            if pid not in relationships:
                return (pid if pid in branch_products else None), [], 'installed_on', True
            component_ref, platform_ref = relationships[pid]
            component, platforms, category, supported = component_scope(component_ref)
            if categories[pid] != 'installed_on':
                category = categories[pid]
            platform = products[platform_ref]
            qualifies = (platform_ref in branch_products and 'version' not in platform
                         and 'range' not in platform)
            platforms = platforms + ([platform['name']] if qualifies else [])
            supported = supported and qualifies and categories[pid] == 'installed_on'
            if component is not None:
                base = products[component]
                products[pid] = dict(base, id=pid)
                keys = {tuple(normalise_identity(part) for part in name.split(':', 1))
                        for name in platforms}
                relationship = dict(category=category)
                if supported and len(keys) == 1 and ('version' in base or 'range' in base):
                    relationship['platform'] = platforms[0]
                scopes[pid] = relationship
            resolved[pid] = component, platforms, category, supported
            return resolved[pid]

        for pid in relationships:
            component_scope(pid)
    return products, scopes


def index_products(document, *, policy=MICROSOFT):
    """Return products keyed by CSAF ID, or mapping_error for invalid content."""
    try:
        return _index(document, policy)[0]
    except (ValueError, TypeError, KeyError, RecursionError):
        return {'mapping_error': 'invalid product tree'}


def normalise(document, *, path, directory_url, policy=MICROSOFT):
    """Return a clock-free member, or {id, mapping_error}; never parse fix prose."""
    identity = None
    try:
        document = _object(document)
        metadata = _object(document.get('document'))
        tracking = _object(metadata.get('tracking'))
        identity = _text(tracking.get('id'))
        if tracking.get('status') == 'draft':
            raise ValueError('draft advisory')
        published = rfc3339(tracking.get('initial_release_date')).raw
        updated = rfc3339(tracking.get('current_release_date')).raw
        products, scopes = _index(document, policy)
        tree = document.get('product_tree', {})
        groups = {}
        for group in tree.get('product_groups', []):
            gid = _text(group.get('group_id'))
            if gid in groups:
                raise ValueError('duplicate group ID')
            groups[gid] = _references(group.get('product_ids'), products)
        facets, cves = [], []
        for vulnerability in _array(document.get('vulnerabilities', [])):
            vulnerability = _object(vulnerability)
            statuses = _object(vulnerability.get('product_status', {}))
            refs, by_product = set(), {}
            for status, ids in statuses.items():
                for pid in _references(ids, products):
                    refs.add(pid)
                    by_product.setdefault(pid, set()).add(status)
            fixes = set()
            for remediation in _array(vulnerability.get('remediations', [])):
                remediation = _object(remediation)
                scoped = set(_references(remediation.get('product_ids', []), products))
                for gid in _array(remediation.get('group_ids', [])):
                    if not isinstance(gid, str) or gid not in groups:
                        raise ValueError('dangling product reference')
                    scoped.update(groups[gid])
                refs.update(scoped)
                if remediation.get('category') == 'vendor_fix':
                    fixes.update(scoped)
            evidence = []
            for pid in products:
                asserted = by_product.get(pid, set())
                positive = 'known_affected' in asserted
                negative = bool(asserted & {'known_not_affected', 'fixed', 'first_fixed'})
                status = ('known_affected' if positive else 'first_fixed' if asserted & {'fixed', 'first_fixed'}
                          else 'known_not_affected' if negative else 'under_investigation' if 'under_investigation' in asserted else None)
                if status is None:
                    continue
                entry = dict(product_id=pid, scheme='opaque', binding='watch', status=status)
                if pid in scopes:
                    entry['relationship'] = scopes[pid]
                if 'range' in products[pid]:
                    entry['range'] = products[pid]['range']
                if asserted & {'fixed', 'first_fixed'} and 'version' in products[pid]:
                    entry['fix'] = products[pid]['version']
                elif pid in fixes:
                    entry['fix'] = 'available'
                if positive and negative:
                    entry['diagnostic'] = 'contradictory status'
                evidence.append(entry)
            ids = []
            for item in _array(vulnerability.get('ids', [])):
                item = _object(item)
                ids.append(dict(system_name=_text(item.get('system_name')), text=_text(item.get('text'))))
            title = vulnerability.get('title', '')
            if not isinstance(title, str):
                raise ValueError('invalid CSAF text')
            facet = dict(title=title, ids=ids,
                         products=[dict(id=pid, name=products[pid]['name']) for pid in products if pid in refs], evidence=evidence)
            cve = vulnerability.get('cve')
            if isinstance(cve, str) and re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', cve):
                facet['cve'] = cve
                if cve not in cves:
                    cves.append(cve)
            facets.append(facet)
        urls = []
        for reference in _array(metadata.get('references', [])):
            reference = _object(reference)
            if reference.get('category') == 'self':
                urls.append(_text(reference.get('url')))
        url = next((u for u in urls if not u.endswith('.json')), urls[0] if urls else directory_url.rstrip('/') + '/' + path)
        return dict(id=identity, title=_text(metadata.get('title')), published=published, updated=updated,
                    url=url, products=[{k: v for k, v in p.items() if k != 'range'} for p in products.values()],
                    cves=cves, evidence=[], facets=facets)
    except (ValueError, TypeError, KeyError, RecursionError) as error:
        # Publisher values must never become diagnostics or escape to a caller.
        reason = str(error) if type(error) is ValueError and str(error) in {
            'dangling product reference', 'relationship cycle', 'draft advisory', 'invalid vendor name'} else 'invalid CSAF document'
        return dict(id=identity, mapping_error=reason)

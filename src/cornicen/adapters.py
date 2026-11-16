# script-purpose: Define adapter gates, settings and the runtime protocol.
# script-class: pipeline-tool
# script-trigger: Adapter configuration, status and engine dispatch.
# script-tests: tests/test_f1.py, tests/test_task1_b1.py, tests/test_task2_b1.py
"""Release gates and the adapter protocol; no factories live in this registry.

Reads install settings; returns validated settings and status without writes.
This library has no process exit codes; callers report configuration errors.
"""
from dataclasses import dataclass
from typing import Protocol

from cornicen.diagnostics import FixedDiagnostic


class AdapterProtocol(Protocol):
    """Runtime interface required from every effective adapter factory.

    Each method returns an iterable of resource outcome dictionaries accepted
    by AdapterStore.process. Resource export flags default to registry policy;
    discovery and metadata outcomes must use export=False when inapplicable.
    """

    def required_resources(self):
        """Independent adapters return the logical resource keys currently watched."""
        ...

    def poll(self, *, cutoff):
        """Return scheduled resource outcomes bounded by the stored cutoff."""
        ...

    def retry(self, resource):
        """Return outcomes for a resource whose retry backoff has elapsed."""
        ...

    def audit(self, resource):
        """Return unconditional outcomes for the named resource's weekly audit.

        Required even for adapters that normally use conditional requests;
        outcomes must omit conditional=True to establish an audit on HTTP 200.
        """
        ...


@dataclass(frozen=True)
class Adapter:
    name: str
    gate_name: str
    gate: str = 'not met'
    export: bool = False
    last_modified_validated: bool = False
    independent: bool = False

    def effective(self, setting):
        return setting is True and self.gate == 'met'


REGISTRY = {name: Adapter(name, gate, export=name in ('debian','ubuntu'), independent=name in ('github', 'msrc')) for name, gate in
            zip(('synology', 'debian', 'ubuntu', 'msrc', 'cisco', 'github'), 'SDUMCG')}


def settings(value):
    if not isinstance(value, dict) or value.keys() - REGISTRY.keys():
        raise ValueError(FixedDiagnostic('adapters must be a table naming known adapters'))
    result = {name: name == 'github' for name in REGISTRY}
    for name, entry in value.items():
        if not isinstance(entry, dict) or entry.keys() - {'enabled'}:
            raise ValueError(FixedDiagnostic('adapter settings only accept enabled'))
        if 'enabled' in entry:
            if type(entry['enabled']) is not bool:
                raise ValueError(FixedDiagnostic('adapter enabled must be a boolean'))
            result[name] = entry['enabled']
    return result


def status(values=None):
    values = settings({}) if values is None else values
    return {name: dict(setting=values[name], gate=entry.gate, gate_name=entry.gate_name,
                       effective=entry.effective(values[name])) for name, entry in REGISTRY.items()}


def status_lines(values):
    return [f'{name}: ' + ('enabled' if entry.effective(values[name]) else
            f'disabled: gate {entry.gate_name} {entry.gate}') +
            f' (setting {"on" if values[name] else "off"})' for name, entry in REGISTRY.items()]

"""Fixed role and position diagnostics for private input files."""

import re


# Keep established public health words when retiring old input diagnostics.
_LEGACY_PUBLIC_WORDS = "Cannot did mean read unnamed you"


class FixedDiagnostic(str):
    """Only fixed source words and integer positions, never input-derived text."""


def file_error(role, error):
    noun = role if role == 'backup destination' else f'{role} file'
    reason = 'not found' if isinstance(error, FileNotFoundError) else 'not readable'
    if role == 'backup destination' and not isinstance(error, FileNotFoundError):
        reason = 'not writable'
    return FixedDiagnostic(f'{noun} {reason}')


def toml_error(role, error, text=None):
    # Python 3.14 exposes positions; older tomllib versions put them in a
    # fixed suffix. Never copy parser prose, which can contain private keys.
    line, column = getattr(error, 'lineno', None), getattr(error, 'colno', None)
    # Attribute presence never establishes fixed provenance. Only integer
    # positions may enter the diagnostic; discard arbitrary attribute text.
    line = line if type(line) is int else None
    column = column if type(column) is int else None
    if line is None:
        position = re.search(r'\(at line ([0-9]+), column ([0-9]+)\)$', str(error))
        if position:
            line, column = map(int, position.groups())
        elif text is not None and str(error).endswith('(at end of document)'):
            line = text.count('\n') + 1
            column = len(text.rsplit('\n', 1)[-1]) + 1
    message = f'{role} file is not valid TOML'
    if line is not None and column is not None:
        message += f' (line {line}, column {column})'
    return FixedDiagnostic(message)


def read_text(path, role):
    try:
        return path.read_text(encoding='utf-8')
    except (OSError, UnicodeError) as error:
        raise ValueError(file_error(role, error)) from None


def token_permissions(role):
    return FixedDiagnostic(f'{role} requires owner-only permissions (mode 0600); '
                           'shared access requires allow_shared_token_file')


def alias_diagnostic(message):
    """Recognize only the fixed alias validator grammar; never trust OS prose."""
    # identity.py is matching-pinned. Its non-parser validation has this closed
    # grammar; roles are source constants and group numbers are integers.
    for role in ('builtin', 'aliases_path'):
        for reason in ('alias map requires a nonempty version',
                       'alias map requires alias groups'):
            if message == f'{role} {reason}':
                return FixedDiagnostic(f'{role} {reason}')
        match = re.fullmatch(re.escape(role) + r' alias group ([0-9]+): (.*)', message)
        if match:
            for reason in ('requires at least two identities',
                           'identity must be vendor:product',
                           'identity must not contain a placeholder vendor or product'):
                if match[2] == reason:
                    return FixedDiagnostic(f'{role} alias group {int(match[1])}: {reason}')
    return None

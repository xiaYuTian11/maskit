"""Local ingress verification contract. No networking, bodies or process identity claims.

Only the reserved, fixed-length marker is excluded from inspection; adjacent text is
still scanned. Events carry bounded SHA-256 digests, never the marker itself.
"""
import hashlib
import re
import secrets
import time

PREFIX = 'MASKIT-' + 'VERIFY-'
ALPHABET = 'BCDFGHJKLMNPQRSTVWXYZ23456789'
MARKER_RE = re.compile(r'(?<![A-Za-z0-9_-])' + PREFIX + '[' + ALPHABET + r']{16}(?![A-Za-z0-9_-])')
TTL = 600


def digest(marker):
    return hashlib.sha256(marker.encode('ascii')).hexdigest()


def scrub(value, *, diagnostic=False):
    """Copy and remove markers, including dictionary keys, before log projection.

    Diagnostic bundles additionally omit correlation digests. Never mutate input:
    the outgoing request must retain the exact marker typed by the user.
    """
    if isinstance(value, str):
        return MARKER_RE.sub('[verification marker]', value)
    if isinstance(value, dict):
        return {scrub(k): scrub(v, diagnostic=diagnostic) for k, v in value.items()
                if not (diagnostic and k == 'verification')}
    if isinstance(value, (list, tuple)):
        return [scrub(v, diagnostic=diagnostic) for v in value]
    return value


def create(ingress, upstream, fingerprint, since, mode='marker', *, now=None):
    if ingress not in ('proxy', 'ext') or mode not in ('marker', 'window'):
        raise ValueError('invalid_verification_scope')
    now = time.time() if now is None else now
    marker = PREFIX + ''.join(secrets.choice(ALPHABET) for _ in range(16)) if mode == 'marker' else None
    return {'id': secrets.token_hex(16), 'ingress': ingress, 'upstream': upstream,
            'mode': mode, 'status': 'pending', 'started_at': now, 'expires_at': now + TTL,
            'fingerprint': fingerprint, 'digest': digest(marker) if marker else '',
            'cursor': since}, marker


def advance(record, rows, fingerprint, *, now=None, exhausted=True):
    now = time.time() if now is None else now
    result = dict(record)
    if fingerprint != record['fingerprint']:
        result['status'] = 'stale'
    elif record['status'] == 'pending':
        for row in rows:
            seq = row.get('seq', 0)
            if seq <= record['cursor']:
                continue
            result['cursor'] = max(result['cursor'], seq)
            if not record['started_at'] <= row.get('ts', 0) <= record['expires_at']:
                continue
            if row.get('type') != 'MASK' or row.get('ingress', 'proxy') != record['ingress']:
                continue
            if record['upstream'] and row.get('upstream') != record['upstream']:
                continue
            if record['mode'] == 'marker' and not (row.get('verification') or {}).get(record['digest']):
                continue
            result['status'] = 'observed'
            result['evidence'] = {k: row[k] for k in ('seq', 'ts', 'sid', 'decision', 'completeness') if k in row}
            break
        if exhausted and result['status'] == 'pending' and now > record['expires_at']:
            result['status'] = 'expired'
    return result


def public(record):
    return {k: v for k, v in record.items() if k not in ('digest', 'fingerprint', 'cursor')}

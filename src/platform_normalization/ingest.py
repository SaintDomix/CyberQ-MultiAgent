"""Bounded deterministic common web format ingestion; no network or file writes."""
import csv
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import re
from urllib.parse import urlsplit
from branch2.adapters.apache import parse_line
from branch2.events import identifier, utc
from .schema import CanonicalWebEvent, NormalizedBatch, FIELDS, digest

MAX_BYTES = 8_000_000
MAX_RECORDS = 20000
MAX_RECORD_BYTES = 131072
ALIASES = {
    'timestamp': ('timestamp', 'time', 'event_time', 'datetime', '@timestamp'),
    'client_id': ('client_id', 'client_ip', 'remote_addr', 'src_ip', 'source_ip', 'ip'),
    'method': ('method', 'http_method', 'request_method', 'verb'),
    'path': ('path', 'uri', 'url', 'request_uri', 'request'),
    'query': ('query', 'query_string', 'args'),
    'status': ('status', 'status_code', 'response_status', 'http_status'),
    'response_bytes': ('response_bytes', 'bytes', 'bytes_sent', 'body_bytes_sent'),
    'user_agent': ('user_agent', 'http_user_agent'), 'referrer': ('referrer', 'referer', 'http_referer'),
    'authenticated_user_id': ('authenticated_user_id', 'user_id', 'remote_user'),
    'session_id': ('session_id',), 'role': ('role',), 'authentication_state': ('authentication_state',),
    'content_type': ('content_type',), 'host': ('host',), 'scheme': ('scheme',),
    'response_time': ('response_time', 'request_time')}
NULL = object()
COMMON = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "(?:\\.|[^"\\])*" \d{3} (?:\d+|-)$')


class MappingRequired(ValueError):
    pass


def detect(text):
    sample = text.strip()
    if not sample: return {'format': None, 'state': 'MAPPING_REQUIRED', 'evidence': 'EMPTY_SOURCE'}
    try:
        value = json.loads(sample)
        if isinstance(value, dict) or isinstance(value, list) and all(isinstance(v, dict) for v in value):
            return {'format': 'json', 'state': 'DETECTED', 'evidence': 'JSON_OBJECT_OR_RECORD_ARRAY'}
    except ValueError: pass
    lines = sample.splitlines()
    try:
        if len(lines) > 1 and all(isinstance(json.loads(s), dict) for s in lines):
            return {'format': 'jsonl', 'state': 'DETECTED', 'evidence': 'ONE_JSON_OBJECT_PER_LINE'}
    except ValueError: pass
    if COMMON.fullmatch(lines[0]) or re.match(r'^\S+ \S+ \S+ \[[^\]]+\] "', lines[0]):
        return {'format': 'access', 'state': 'DETECTED', 'evidence': 'COMMON_COMBINED_SYNTAX; server vendor cannot be inferred'}
    try:
        header = next(csv.reader(io.StringIO(sample)))
        recognized = sum(any(h in choices for h in header) for choices in ALIASES.values())
        if len(header) > 1 and len(header) == len(set(header)) and recognized >= 2:
            return {'format': 'csv', 'state': 'DETECTED', 'evidence': 'CSV_HEADER_WITH_MULTIPLE_KNOWN_FIELDS'}
    except (csv.Error, StopIteration): pass
    return {'format': None, 'state': 'MAPPING_REQUIRED', 'evidence': 'UNRECOGNIZED_OR_AMBIGUOUS_FORMAT'}


def validate_mapping(mapping):
    if not isinstance(mapping, dict) or set(mapping) - set(FIELDS) - {'source_platform'}:
        raise ValueError('INVALID_MAPPING_KEYS')
    for key, spec in mapping.items():
        if isinstance(spec, str):
            if not spec or len(spec) > 150: raise ValueError('INVALID_MAPPING_PATH')
        elif isinstance(spec, dict):
            if set(spec) not in ({'field'}, {'constant'}): raise ValueError('INVALID_MAPPING_SPEC')
            if 'field' in spec and (not isinstance(spec['field'], str) or not spec['field'] or len(spec['field']) > 150):
                raise ValueError('INVALID_MAPPING_PATH')
            if 'constant' in spec and not isinstance(spec['constant'], (str, int, float, type(None))):
                raise ValueError('INVALID_MAPPING_CONSTANT')
            if 'constant' in spec and (isinstance(spec['constant'], str) and len(spec['constant']) > 65536
                    or isinstance(spec['constant'], float) and not math.isfinite(spec['constant'])):
                raise ValueError('INVALID_MAPPING_CONSTANT')
        else: raise ValueError('INVALID_MAPPING_SPEC')


def lookup(row, key):
    if key in row: return row[key]
    value = row
    for part in key.split('.'):
        if not isinstance(value, dict) or part not in value: return NULL
        value = value[part]
    return value


def integer(value, code):
    if isinstance(value, bool) or not re.fullmatch(r'\d+', str(value)): raise ValueError(code)
    return int(value)


def structured(row, mapping, source, number, record_hash):
    if not isinstance(row, dict): raise ValueError('RECORD_NOT_OBJECT')
    values = {}; bindings = {}
    for key in FIELDS + ('source_platform',):
        if key in mapping:
            spec = mapping[key]
            if isinstance(spec, dict) and 'constant' in spec:
                value = spec['constant']; name = '<constant>'
            else:
                name = spec['field'] if isinstance(spec, dict) else spec
                value = lookup(row, name)
        else:
            names = [name for name in ALIASES.get(key, ()) if name in row]
            if len(names) > 1: raise MappingRequired('AMBIGUOUS_ALIAS_' + key.upper())
            name = names[0] if names else None
            value = row[name] if name else NULL
        bindings[key] = name
        if value is not NULL and value is not None:
            if value == '-' and key in ('response_bytes', 'user_agent', 'referrer', 'authenticated_user_id', 'session_id', 'role'): continue
            values[key] = value
    observed = set(values) & set(FIELDS)
    if not observed: raise ValueError('NO_RECOGNIZED_FIELDS')
    if 'timestamp' in values:
        ts = values['timestamp']
        try:
            # Epoch timestamps are accepted only as numbers, never guessed units.
            values['timestamp'] = datetime.fromtimestamp(ts, timezone.utc) if type(ts) in (float, int) else utc(str(ts))
        except (ValueError, OverflowError, TypeError, OSError): raise ValueError('TIMESTAMP_INVALID') from None
    raw_client = values.get('client_id')
    for key in ('client_id', 'authenticated_user_id', 'session_id'):
        if key in values:
            if not isinstance(values[key], (str, int)) or isinstance(values[key], bool) or not str(values[key]):
                raise ValueError('IDENTIFIER_INVALID')
            values[key] = identifier(str(values[key]))
    if 'path' in values:
        target = values['path']
        if not isinstance(target, str) or len(target) > 65536 or any(ord(c) < 32 for c in target):
            raise ValueError('URL_INVALID')
        if bindings['path'] == 'request':
            parts = target.split(' ')
            if len(parts) != 3 or not re.fullmatch(r'HTTP/\d(?:\.\d)?', parts[2]): raise ValueError('REQUEST_LINE_INVALID')
            if 'method' in values and str(values['method']).upper() != parts[0].upper(): raise MappingRequired('METHOD_CONFLICT')
            values['method'] = parts[0]; observed.add('method'); target = parts[1]
        try:
            u = urlsplit(target)
            if u.fragment or u.username or u.password or (u.scheme and u.scheme not in ('http', 'https')) or (u.scheme and not u.hostname):
                raise ValueError('URL_INVALID')
            if u.netloc and not u.scheme: raise ValueError('URL_INVALID')
            _ = u.port
        except ValueError: raise ValueError('URL_INVALID') from None
        if not (u.path.startswith('/') or u.path == '*'): raise ValueError('URL_INVALID')
        values['path'] = u.path
        # A path-only field does not prove the query was observed. Full request
        # targets do; an explicit query mapping also does, including empty string.
        full_target = bindings['path'] in ('uri', 'url', 'request_uri', 'request') or '?' in target or bool(u.scheme)
        if full_target:
            if 'query' in values and values['query'] != u.query: raise MappingRequired('QUERY_CONFLICT')
            values['query'] = u.query; observed.add('query')
        if u.hostname:
            values.setdefault('host', u.hostname.lower()); values.setdefault('scheme', u.scheme)
            observed.update(('host', 'scheme'))
    if 'method' in values:
        if not isinstance(values['method'], str) or not re.fullmatch('[A-Za-z]+', values['method']): raise ValueError('METHOD_INVALID')
        values['method'] = values['method'].upper()
    if 'status' in values:
        values['status'] = integer(values['status'], 'STATUS_INVALID')
        if not 100 <= values['status'] <= 599: raise ValueError('STATUS_INVALID')
    if 'response_bytes' in values: values['response_bytes'] = integer(values['response_bytes'], 'BYTES_INVALID')
    for key in ('query', 'user_agent', 'referrer', 'role', 'authentication_state', 'content_type', 'host', 'scheme'):
        if key in values and (not isinstance(values[key], str) or len(values[key]) > 65536): raise ValueError('TEXT_FIELD_INVALID')
    for key in ('host', 'scheme'):
        if key in values: values[key] = values[key].lower()
    if 'scheme' in values and values['scheme'] not in ('http', 'https'): raise ValueError('SCHEME_INVALID')
    if 'response_time' in values:
        if isinstance(values['response_time'], bool): raise ValueError('RESPONSE_TIME_INVALID')
        values['response_time'] = float(values['response_time'])
        if not math.isfinite(values['response_time']) or values['response_time'] < 0: raise ValueError('RESPONSE_TIME_INVALID')
    platform = values.pop('source_platform', 'generic_web')
    if platform not in ('generic_web', 'moodle'): raise ValueError('UNKNOWN_PLATFORM_ID')
    dummy = raw_client in ('::1', '127.0.0.1') and values.get('method') == 'OPTIONS' and values.get('path') == '*' and 'internal dummy connection' in values.get('user_agent', '')
    event = CanonicalWebEvent(**values, observed_fields=tuple(sorted(observed)), source_platform=platform,
        infrastructure_dummy=dummy,
        source_type=source['format'], source_file=source['reference'], source_sha256=source['sha256'],
        line_number=number, record_sha256=record_hash, mapping_sha256=source['mapping_sha256'])
    return event, {k: name for k, name in bindings.items() if name is not None}


def from_legacy(event, source_type='apache', platform='moodle'):
    # Preserve hashed IDs and record/line provenance without a second hash pass.
    values = {k: getattr(event, k) for k in FIELDS if hasattr(event, k)}
    observed = tuple(sorted(k for k, v in values.items() if v is not None))
    return CanonicalWebEvent(**values, observed_fields=observed, infrastructure_dummy=event.infrastructure_dummy,
        source_platform=platform, source_type=source_type, adapter_id='moodle-compatible-apache-1.0' if platform == 'moodle' else 'generic-web-1.0',
        source_file=event.source_file, source_sha256=event.source_sha256, line_number=event.line_number,
        record_sha256=event.record_sha256)


def ingest(raw, *, format=None, mapping=None, source_reference='<memory>', platform='generic_web'):
    if platform not in ('generic_web', 'moodle'): raise ValueError('UNKNOWN_PLATFORM_ID')
    if isinstance(raw, str): raw = raw.encode('utf8')
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES: raise ValueError('SOURCE_SIZE_LIMIT')
    text = raw.decode('utf8', errors='strict')
    mapping = {} if mapping is None else mapping; validate_mapping(mapping)
    detection = detect(text) if not format else {'format': format, 'state': 'EXPLICIT', 'evidence': 'OPERATOR_SELECTED_FORMAT'}
    fmt = detection['format']
    if fmt not in (None, 'json', 'jsonl', 'csv', 'apache', 'nginx', 'access'): raise ValueError('UNSUPPORTED_FORMAT')
    if mapping and fmt in ('access', 'apache', 'nginx'):
        raise ValueError('FIELD_MAPPING_REQUIRES_STRUCTURED_FORMAT')
    detection['adapter_selected'] = ('common-combined-compatibility-1.0' if fmt in ('access', 'apache', 'nginx') else
                                     'structured-'+fmt+'-1.0' if fmt else None)
    source = {'reference': source_reference, 'sha256': hashlib.sha256(raw).hexdigest(), 'format': fmt,
        'mapping_sha256': digest(mapping), 'platform': platform, 'adapter_version': 'universal-web-ingestion-1.0'}
    # Configuration hashes are public; configured constants and values are not.
    mapping_meta = {'sha256': source['mapping_sha256'], 'explicit_fields': sorted(mapping),
                    'resolved_fields': {}, 'alias_catalog_sha256': digest(ALIASES)}
    quality = {'input_records': 0, 'parsed_records': 0, 'rejected_records': 0, 'timestamp_failures': 0,
        'malformed_urls': 0, 'malformed_status': 0, 'malformed_bytes': 0, 'mapping_warnings': [],
        'errors': [], 'canonical_events_emitted': 0, 'missing_required_fields': {}, 'missing_optional_fields': {}}
    if fmt is None: return NormalizedBatch([], source, detection, quality, mapping_meta, 'MAPPING_REQUIRED')
    try:
        if fmt == 'json':
            records = json.loads(text); records = [records] if isinstance(records, dict) else records
            if not isinstance(records, list): raise ValueError('JSON_RECORDS_REQUIRED')
        elif fmt == 'csv':
            reader = csv.DictReader(io.StringIO(text))
            if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames): raise MappingRequired('DUPLICATE_CSV_COLUMNS')
            records = list(reader)
        else: records = text.splitlines()
    except (ValueError, csv.Error):
        quality['errors'].append({'reason': 'SOURCE_SYNTAX_OR_HEADER_INVALID'})
        return NormalizedBatch([], source, detection, quality, mapping_meta, 'FAILED')
    if len(records) > MAX_RECORDS: raise ValueError('RECORD_COUNT_LIMIT')
    events = []; ambiguous = False
    for number, record in enumerate(records, 1):
        quality['input_records'] += 1
        encoded = record.encode() if isinstance(record, str) else json.dumps(record, sort_keys=True, default=str).encode()
        rh = hashlib.sha256(encoded).hexdigest()
        try:
            if len(encoded) > MAX_RECORD_BYTES: raise ValueError('RECORD_SIZE_LIMIT')
            if fmt in ('access', 'apache', 'nginx'):
                line = record
                if COMMON.fullmatch(line): line += ' "-" "-"'
                try:
                    event = parse_line(line, source_reference, source['sha256'], number)
                except ValueError as exc:
                    message = str(exc)
                    if message == 'Invalid HTTP status': raise ValueError('STATUS_INVALID') from None
                    if message.startswith(('time data ', 'unconverted data remains:')):
                        raise ValueError('TIMESTAMP_INVALID') from None
                    raise ValueError('ACCESS_RECORD_INVALID') from None
                event = from_legacy(event, fmt, platform)
                event = replace(event, record_sha256=rh, mapping_sha256=source['mapping_sha256'])
            else:
                if fmt == 'jsonl': record = json.loads(record)
                if fmt == 'csv' and (None in record or any(v is None for v in record.values())): raise ValueError('CSV_ROW_WIDTH_INVALID')
                event, bindings = structured(record, mapping, source, number, rh)
                for field, name in bindings.items():
                    names = mapping_meta['resolved_fields'].setdefault(field, [])
                    if name not in names: names.append(name); names.sort()
                if 'source_platform' not in mapping: event = replace(event, source_platform=platform)
            events.append(event); quality['parsed_records'] += 1
        except (ValueError, TypeError, OverflowError) as exc:
            code = str(exc) if re.fullmatch('[A-Z_]+', str(exc)) else 'RECORD_INVALID'
            ambiguous |= isinstance(exc, MappingRequired)
            quality['rejected_records'] += 1
            quality['timestamp_failures'] += code == 'TIMESTAMP_INVALID'
            for field, reason in [('malformed_urls', 'URL_INVALID'), ('malformed_status', 'STATUS_INVALID'), ('malformed_bytes', 'BYTES_INVALID')]:
                quality[field] += code == reason
            if len(quality['errors']) < 20: quality['errors'].append({'record': number, 'sha256': rh, 'reason': code})
            if isinstance(exc, MappingRequired) and code not in quality['mapping_warnings']: quality['mapping_warnings'].append(code)
    from .dependencies import REQUIRED
    quality['canonical_events_emitted'] = len(events)
    for k in FIELDS:
        n = sum(k in e.missing_fields for e in events)
        if n: quality['missing_required_fields' if k in REQUIRED else 'missing_optional_fields'][k] = n
    state = 'MAPPING_REQUIRED' if ambiguous else 'FAILED' if not events else 'PARTIAL' if quality['rejected_records'] else 'COMPLETE'
    return NormalizedBatch(events, source, detection, quality, mapping_meta, state)

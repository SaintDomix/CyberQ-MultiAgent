"""Durable projection of frozen episode semantics from authoritative observations."""
import hashlib
import json

from branch2.live_storage import IntegrityFault, atomic_json, digest, encode


class Incidents:
    def __init__(self, journal, persistence, model_id):
        self.journal, self.db = journal, journal.db
        self.persistence, self.model_id = persistence, model_id
        self.db.execute('CREATE TABLE IF NOT EXISTS episode_cursor (singleton INTEGER PRIMARY KEY CHECK(singleton=1), sequence INTEGER NOT NULL)')
        self.db.execute('INSERT OR IGNORE INTO episode_cursor VALUES (1,0)')
        self.db.execute('CREATE TABLE IF NOT EXISTS episode_groups (group_id TEXT PRIMARY KEY, payload TEXT NOT NULL, sha256 TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS incidents (episode_id TEXT PRIMARY KEY, payload TEXT NOT NULL, sha256 TEXT NOT NULL)')
        self.db.commit()
        self.sync()

    @staticmethod
    def checked(payload, expected):
        if hashlib.sha256(payload.encode()).hexdigest() != expected:
            raise IntegrityFault('EPISODE_JOURNAL_HASH_MISMATCH')
        return json.loads(payload)

    def sync(self):
        high = self.db.execute('SELECT sequence FROM episode_cursor WHERE singleton=1').fetchone()[0]
        if high > self.journal.sequence:
            raise IntegrityFault('EPISODE_JOURNAL_AHEAD_OF_OBSERVATIONS')
        rows = self.db.execute('SELECT sequence,payload,sha256 FROM results WHERE sequence>? ORDER BY sequence', (high,))
        for sequence, payload, expected in rows:
            p = self.checked(payload, expected)['prediction']
            if sequence != high + 1:
                raise IntegrityFault('EPISODE_OBSERVATION_SEQUENCE_GAP')
            key = digest([p['session_id'], p['client_id'], p['user_agent_id'], self.model_id])
            stored = self.db.execute('SELECT payload,sha256 FROM episode_groups WHERE group_id=?', (key,)).fetchone()
            prior = self.checked(*stored) if stored else None
            decision = p['reconciliation']['decision']
            if prior and prior['behavior_class'] == decision and prior['end'] == p['window_start']:
                e = prior
            else:
                e = {'episode_id': digest([key, decision, p['window_start']]),
                     'model_id': self.model_id, 'session_id': p['session_id'],
                     'client_id': p['client_id'], 'user_agent_id': p['user_agent_id'],
                     'behavior_class': decision, 'start': p['window_start'], 'end': p['window_end'],
                     'observation_ids': [], 'member_count': 0, 'model_disagreement_visible': False,
                     'successful_exploitation_confirmed': False, 'causal': False}
            e['end'] = p['window_end']
            e['member_count'] += 1
            e['observation_ids'].append(p['observation_id'])
            e['model_disagreement_visible'] |= p['reconciliation']['model_disagreement']
            known = decision not in ('BENIGN', 'UNKNOWN_ANOMALY', 'UNCERTAIN')
            e['state'] = ('KNOWN_THREAT_ATTEMPT_EPISODE' if known else
                          'UNKNOWN_ANOMALY_EPISODE' if decision == 'UNKNOWN_ANOMALY' and e['member_count'] >= self.persistence else
                          'NOVEL_OBSERVATION' if decision in ('UNKNOWN_ANOMALY', 'UNCERTAIN') else 'BENIGN')
            e['alert'] = e['state'] in ('KNOWN_THREAT_ATTEMPT_EPISODE', 'UNKNOWN_ANOMALY_EPISODE')
            e['severity_semantics'] = 'known attempt pattern' if known else 'unclassified anomaly observation; not an exploitation claim'
            serialized = encode(e)
            value_hash = hashlib.sha256(serialized.encode()).hexdigest()
            with self.db:
                self.db.execute('INSERT OR REPLACE INTO episode_groups VALUES (?,?,?)', (key, serialized, value_hash))
                if e['alert']:
                    self.db.execute('INSERT OR REPLACE INTO incidents VALUES (?,?,?)', (e['episode_id'], serialized, value_hash))
                self.db.execute('UPDATE episode_cursor SET sequence=? WHERE singleton=1', (sequence,))
            high = sequence
        # Atomic replaceable projection; SQLite is authoritative. Growing one
        # episode updates its existing stable ID rather than appending incidents.
        atomic_json(self.journal.root / 'incidents.json', self.values())

    def values(self):
        return [self.checked(payload, expected) for payload, expected in
                self.db.execute('SELECT payload,sha256 FROM incidents ORDER BY episode_id')]

"""Coursework-owned SQLite task state and append-only hash-chained audit events."""
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from .models import TaskState, now, TaskError, TERMINAL, Failure
from coursework.isolation import STATE


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class Store:
    def __init__(self, root=None):
        self.root = Path(root or STATE/'multiagent').resolve()
        if not self.root.is_relative_to(STATE) or self.root == STATE or self.root.is_symlink():
            raise ValueError('Only dedicated coursework task storage is allowed')
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.root/'tasks.sqlite3'
        self.lock = threading.RLock()
        with self.connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY, request_id TEXT UNIQUE, created_at TEXT NOT NULL, state TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (
                task_id TEXT NOT NULL, sequence INTEGER NOT NULL, payload TEXT NOT NULL,
                previous_sha256 TEXT NOT NULL, sha256 TEXT NOT NULL,
                PRIMARY KEY(task_id,sequence), FOREIGN KEY(task_id) REFERENCES tasks(task_id));''')
            db.execute('CREATE TABLE IF NOT EXISTS rejections (rejection_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, code TEXT NOT NULL, source TEXT NOT NULL)')

    def official(self):
        """Latest eligible full task, never a mutable branch/research calculation.

        Derive from committed completion events, including pre-existing tasks;
        there is no branch endpoint capable of publishing this selection.
        """
        with self.lock,self.connect() as db:
            rows=db.execute("SELECT t.state FROM tasks t JOIN events e ON t.task_id=e.task_id "
                "WHERE json_extract(e.payload,'$.event')='task.completed' "
                "ORDER BY json_extract(e.payload,'$.timestamp') DESC").fetchall()
        for row in rows:
            state=TaskState.model_validate_json(row[0])
            result=state.result or {};q=result.get('cqi') or {}
            if (state.status=='COMPLETED' and result.get('consistency_with_existing_cqi')=='PASS'
                    and result.get('assessment_outcome')!='TEST_ONLY_LIVE_INTEGRATION'
                    and q.get('overall') is not None and len(q.get('dimensions',[]))==6
                    and q.get('policy',{}).get('version')=='cqi-evidence-2.0'):
                return state
        return None

    def reject(self,code,source):
        with self.lock,self.connect() as db:
            db.execute('INSERT INTO rejections VALUES(?,?,?,?)',('reject-'+uuid.uuid4().hex,now(),code,source))

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=3)
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA journal_mode=WAL')
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def by_request(self, request_id):
        if not request_id: return None
        with self.lock, self.connect() as db:
            row=db.execute('SELECT state FROM tasks WHERE request_id=?',(request_id,)).fetchone()
        return TaskState.model_validate_json(row[0]) if row else None

    def create(self, state):
        with self.lock, self.connect() as db:
            db.execute('INSERT INTO tasks VALUES(?,?,?,?)', (state.task_id,state.request.request_id,state.created_at,state.model_dump_json()))

    def get(self, task_id):
        with self.lock, self.connect() as db:
            row=db.execute('SELECT state FROM tasks WHERE task_id=?',(task_id,)).fetchone()
        if not row: raise TaskError('TASK_NOT_FOUND','Unknown coursework task')
        return TaskState.model_validate_json(row[0])

    def list(self, limit=20):
        with self.lock, self.connect() as db:
            rows=db.execute('SELECT state FROM tasks ORDER BY created_at DESC LIMIT ?', (limit,)).fetchall()
        return [TaskState.model_validate_json(r[0]) for r in rows]

    def record(self, state, event, agent='coordinator', **details):
        """State transition and corresponding event commit in one transaction."""
        state.updated_at=now()
        with self.lock, self.connect() as db:
            saved=db.execute('SELECT state FROM tasks WHERE task_id=?',(state.task_id,)).fetchone()
            if saved:
                previous_status=json.loads(saved[0])['status']
                if previous_status in TERMINAL and previous_status!=state.status:
                    raise TaskError('TERMINAL_STATE_IMMUTABLE','A terminal task cannot transition to a different state')
                final=db.execute('SELECT payload FROM events WHERE task_id=? ORDER BY sequence DESC LIMIT 1',(state.task_id,)).fetchone()
                if final and json.loads(final[0])['event'] in ('task.completed','task.failed','task.interrupted'):
                    raise TaskError('TERMINAL_STATE_IMMUTABLE','Completed task snapshots and their audit trail are immutable')
            old=db.execute('SELECT sequence,sha256 FROM events WHERE task_id=? ORDER BY sequence DESC LIMIT 1',(state.task_id,)).fetchone()
            sequence, previous = (old[0]+1,old[1]) if old else (1,'0'*64)
            value={'schema_version':'cqma-event-1.0','task_id':state.task_id,'sequence':sequence,
                   'timestamp':state.updated_at,'event':event,'agent':agent,**details}
            payload=canonical(value);sha=hashlib.sha256((previous+payload).encode()).hexdigest()
            db.execute('INSERT INTO events VALUES(?,?,?,?,?)',(state.task_id,sequence,payload,previous,sha))
            db.execute('UPDATE tasks SET state=? WHERE task_id=?',(state.model_dump_json(),state.task_id))

    def events(self, task_id):
        with self.lock,self.connect() as db:
            rows=db.execute('SELECT sequence,payload,previous_sha256,sha256 FROM events WHERE task_id=? ORDER BY sequence',(task_id,)).fetchall()
        result=[]; previous='0'*64
        for sequence,payload,expected,sha in rows:
            if sequence!=len(result)+1 or expected!=previous or hashlib.sha256((previous+payload).encode()).hexdigest()!=sha:
                raise TaskError('AUDIT_INTEGRITY_FAILED','Task audit chain failed verification')
            result.append({**json.loads(payload),'previous_sha256':previous,'sha256':sha});previous=sha
        return result

    def export(self, task_id):
        state=self.get(task_id)
        return {'state':public_state(state),'events':self.events(task_id),
                'audit_semantics':'Hash-chained local audit; detects accidental corruption, not a signed external attestation'}

    def recover(self):
        """Called only while holding the exclusive global runner lock."""
        with self.connect() as db:
            rows=db.execute('SELECT state FROM tasks').fetchall()
        for row in rows:
            state=TaskState.model_validate_json(row[0])
            if state.status not in TERMINAL:
                state.status='INTERRUPTED'
                state.agents={k:('INTERRUPTED' if v=='RUNNING' or k=='coordinator' else 'SKIPPED' if v=='PENDING' else v) for k,v in state.agents.items()}
                state.failure=Failure(code='PROCESS_INTERRUPTED',message='Previous process ended; no automatic task resume or assessment success asserted')
                self.record(state,'task.interrupted',reason='Previous process ended; task is never automatically replayed')


def public_state(state):
    from demo.backend.privacy import sanitize
    # Raw source records/feature joins remain private internal state, not API/log output.
    return sanitize(state.model_dump(mode='json',exclude={'tool_outputs'}))
